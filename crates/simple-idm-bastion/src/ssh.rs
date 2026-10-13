use crate::config::{Config, Host};
use anyhow::{Context, Result, ensure};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::mpsc,
};

#[derive(Serialize)]
struct SignRequest<'a> {
    public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_principals: Option<&'a Vec<String>>,
    ttl_seconds: u64,
    session_id: &'a str,
}
#[derive(Deserialize)]
pub struct SignedCertificate {
    pub certificate: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub principals: Vec<String>,
}
pub struct Prepared {
    pub dir: tempfile::TempDir,
    pub listener: UnixListener,
    pub nonce: String,
    pub certificate_id: String,
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
async fn keygen(args: &[&str]) -> Result<String> {
    let mut command = tokio::process::Command::new("/usr/bin/ssh-keygen");
    command
        .args(args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null());
    let output = tokio::time::timeout(Duration::from_secs(10), command.output()).await??;
    ensure!(output.status.success(), "ssh-keygen failed");
    Ok(String::from_utf8(output.stdout)?)
}
impl Prepared {
    pub async fn new(
        config: &Config,
        host: &Host,
        session_id: &str,
        token: &str,
        secret: &str,
        http: &reqwest::Client,
    ) -> Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("session-")
            .tempdir_in(&config.session_dir)?;
        let key = dir.path().join("identity");
        keygen(&[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            session_id,
            "-f",
            key.to_str().context("key path UTF-8")?,
        ])
        .await?;
        let public_key = tokio::fs::read_to_string(key.with_extension("pub")).await?;
        let response = http
            .post(&config.signer_url)
            .bearer_auth(token)
            .header("X-Bastion-Key", secret)
            .json(&SignRequest {
                public_key: public_key.trim(),
                requested_principals: host.principals.as_ref(),
                ttl_seconds: config.ttl_seconds,
                session_id,
            })
            .send()
            .await
            .context("signer unavailable")?;
        // Never reflect the signer's body (which can contain sensitive details).
        ensure!(
            response.status().is_success(),
            "signer rejected delegation (HTTP {})",
            response.status().as_u16()
        );
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 65536,
                "signer response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let cert: SignedCertificate =
            serde_json::from_slice(&bytes).context("invalid signer response")?;
        validate_response(&cert, host, config.ttl_seconds)?;
        let path = dir.path().join("identity-cert.pub");
        tokio::fs::write(&path, &cert.certificate).await?;
        let description =
            keygen(&["-L", "-f", path.to_str().context("certificate path UTF-8")?]).await?;
        let key_id = description
            .lines()
            .find_map(|l| l.trim().strip_prefix("Key ID: "))
            .context("missing certificate key ID")?;
        let serial = description
            .lines()
            .find_map(|l| l.trim().strip_prefix("Serial: "))
            .context("missing certificate serial")?;
        ensure!(
            description.contains(" user certificate"),
            "signer returned a non-user certificate"
        );
        // ssh-keygen fingerprints the underlying public key for a certificate.
        let cert_fp = keygen(&["-l", "-f", path.to_str().unwrap()]).await?;
        let key_fp = keygen(&["-l", "-f", key.with_extension("pub").to_str().unwrap()]).await?;
        ensure!(
            cert_fp.split_whitespace().nth(1) == key_fp.split_whitespace().nth(1),
            "certificate does not match session key"
        );
        let mut in_principals = false;
        let mut actual_principals = Vec::new();
        for line in description.lines() {
            let text = line.trim();
            if text == "Principals:" {
                in_principals = true;
                continue;
            }
            if in_principals {
                if text.starts_with("Critical Options:") || text.starts_with("Extensions:") {
                    break;
                }
                actual_principals.push(text.to_owned());
            }
        }
        ensure!(
            !actual_principals.is_empty()
                && actual_principals
                    .iter()
                    .all(|p| cert.principals.contains(p))
                && cert
                    .principals
                    .iter()
                    .all(|p| actual_principals.contains(p)),
            "certificate principals differ from signer metadata"
        );
        let socket = dir.path().join("ready.sock");
        let listener = UnixListener::bind(&socket)?;
        Ok(Self {
            dir,
            listener,
            nonce: uuid::Uuid::new_v4().to_string(),
            certificate_id: format!("{key_id};serial={serial}"),
        })
    }
    pub fn spawn_files(
        &self,
        config: &Config,
        host: &Host,
        login: &str,
        sudo_readonly: bool,
    ) -> Result<tokio::process::Child> {
        let command = ssh_command(
            config,
            host,
            login,
            self.dir.path(),
            &self.nonce,
            true,
            sudo_readonly,
        )?;
        let argv = command.get_argv();
        let mut process = tokio::process::Command::new(&argv[0]);
        process
            .args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("SSH_ASKPASS_REQUIRE", "never")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        Ok(process.spawn()?)
    }
    pub async fn marker(&self) -> Result<tokio::net::UnixStream> {
        let (mut stream, _) = self.listener.accept().await?;
        let mut nonce = vec![0; self.nonce.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut nonce)).await??;
        ensure!(
            nonce == self.nonce.as_bytes(),
            "invalid local authentication marker"
        );
        Ok(stream)
    }
    pub fn spawn(
        &self,
        config: &Config,
        host: &Host,
        login: &str,
        cols: u16,
        rows: u16,
        term: &str,
    ) -> Result<Transport> {
        let pair = native_pty_system().openpty(size(cols, rows))?;
        let original_local_flags = pair
            .master
            .get_termios()
            .context("PTY termios unavailable")?
            .local_flags
            .bits()
            .to_ne_bytes()
            .to_vec();
        let mut command = ssh_command(
            config,
            host,
            login,
            self.dir.path(),
            &self.nonce,
            false,
            false,
        )?;
        command.env_clear();
        command.env("PATH", "/usr/bin:/bin");
        command.env("TERM", term);
        command.env("SSH_ASKPASS_REQUIRE", "never");
        command.env("SHELL", "/bin/sh");
        let mut child = pair.slave.spawn_command(command)?;
        drop(pair.slave);
        let reader = match pair.master.try_clone_reader() {
            Ok(r) => r,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let writer = match pair.master.take_writer() {
            Ok(w) => w,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let (output_tx, output) = mpsc::channel(16);
        std::thread::spawn(move || {
            let mut reader = reader;
            let mut buf = [0; 16384];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if output_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    // Linux PTY reports EIO once slave closes.
                    Err(e) if e.raw_os_error() == Some(5) => break,
                    Err(e) => {
                        tracing::debug!(error=%e, "PTY read ended");
                        break;
                    }
                }
            }
        });
        let (input, mut input_rx) = mpsc::channel::<Vec<u8>>(16);
        std::thread::spawn(move || {
            let mut writer = writer;
            while let Some(bytes) = input_rx.blocking_recv() {
                if writer
                    .write_all(&bytes)
                    .and_then(|_| writer.flush())
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Transport {
            master: pair.master,
            child,
            input,
            output,
            original_local_flags,
        })
    }
}
pub fn validate_response(cert: &SignedCertificate, host: &Host, ttl: u64) -> Result<()> {
    let now = crate::audit::now() / 1000;
    ensure!(
        cert.valid_after <= now
            && cert.valid_before > now
            && cert.valid_before <= now + ttl as i64 + 60
            && cert.valid_before > cert.valid_after,
        "invalid certificate validity"
    );
    ensure!(!cert.principals.is_empty(), "signer returned no principals");
    if let Some(requested) = &host.principals {
        ensure!(
            cert.principals.iter().all(|p| requested.contains(p)),
            "signer widened requested principals"
        );
    }
    ensure!(
        cert.certificate
            .trim()
            .starts_with("ssh-ed25519-cert-v01@openssh.com ")
            && !cert.certificate.trim().contains(['\n', '\r']),
        "invalid session certificate"
    );
    Ok(())
}
pub fn size(cols: u16, rows: u16) -> PtySize {
    PtySize {
        cols,
        rows,
        pixel_width: 0,
        pixel_height: 0,
    }
}
fn ssh_command(
    config: &Config,
    host: &Host,
    login: &str,
    dir: &Path,
    nonce: &str,
    files: bool,
    sudo_readonly: bool,
) -> Result<CommandBuilder> {
    let mut cmd = CommandBuilder::new("/usr/bin/ssh");
    cmd.args([
        "-F",
        "/dev/null",
        if files { "-T" } else { "-tt" },
        "-p",
        &host.port.to_string(),
        "-l",
        login,
    ]);
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "UpdateHostKeys=no",
        "VerifyHostKeyDNS=no",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=yes",
        "ControlMaster=no",
        "ControlPath=none",
        "EscapeChar=none",
        "ConnectTimeout=20",
        "ConnectionAttempts=1",
        "ServerAliveInterval=20",
        "ServerAliveCountMax=3",
        "LogLevel=ERROR",
        "EnableEscapeCommandline=no",
    ] {
        cmd.args(["-o", option]);
    }
    // Quote paths for OpenSSH's config parser, as well as LocalCommand's shell.
    for (name, path) in [
        ("UserKnownHostsFile", config.known_hosts.clone()),
        ("IdentityFile", dir.join("identity")),
        ("CertificateFile", dir.join("identity-cert.pub")),
    ] {
        let value = path.to_str().context("SSH path UTF-8")?;
        ensure!(
            !value.contains(['"', '\\', '%', '\n', '\r']),
            "unsupported SSH path characters"
        );
        cmd.args(["-o", &format!("{name}=\"{value}\"")]);
    }
    let exe = std::env::current_exe()?;
    let exe = exe.to_str().context("daemon executable path UTF-8")?;
    ensure!(
        !exe.contains('%'),
        "daemon executable path contains OpenSSH expansion"
    );
    let local = format!(
        "LocalCommand={} notify --socket {} --nonce {}",
        quote(exe),
        quote(dir.join("ready.sock").to_str().unwrap()),
        quote(nonce)
    );
    cmd.args(["-o", &local]);
    if files && !sudo_readonly {
        cmd.arg("-s");
    }
    cmd.args(["--", &host.address]);
    if sudo_readonly {
        ensure!(
            files && host.sftp_sudo_readonly,
            "root read-only SFTP denied"
        );
        cmd.args(["/usr/bin/sudo", "-n", "--", &host.sftp_server, "-R"]);
    } else if files {
        cmd.arg("sftp");
    }
    Ok(cmd)
}
pub struct Transport {
    pub master: Box<dyn MasterPty + Send>,
    pub child: Box<dyn Child + Send + Sync>,
    pub input: mpsc::Sender<Vec<u8>>,
    pub output: mpsc::Receiver<Vec<u8>>,
    original_local_flags: Vec<u8>,
}
impl Transport {
    pub fn entered_raw_mode(&self) -> Result<bool> {
        let flags = self
            .master
            .get_termios()
            .context("PTY termios unavailable")?
            .local_flags
            .bits()
            .to_ne_bytes()
            .to_vec();
        // OpenSSH is the sole slave process and changes these flags in its
        // enter_raw_mode after saving the normal modes for the remote PTY.
        Ok(flags != self.original_local_flags)
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
/// LocalCommand blocks until the daemon durably records connection and releases it.
/// No terminal bytes are used for readiness, so remote output cannot spoof it.
pub fn notify(socket: &Path, nonce: &str) -> Result<()> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(nonce.as_bytes())?;
    let mut ack = [0];
    stream.read_exact(&mut ack)?;
    ensure!(ack == [1], "daemon refused authentication marker");
    Ok(())
}
pub async fn release(mut stream: tokio::net::UnixStream) -> Result<()> {
    stream.write_all(&[1]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signer_must_not_widen_principals() {
        let config: Config = toml::from_str(include_str!("../examples/bastion.toml")).unwrap();
        let now = crate::audit::now() / 1000;
        let mut response = SignedCertificate {
            certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".into(),
            valid_after: now - 30,
            valid_before: now + 60,
            principals: vec!["infra-admins".into()],
        };
        validate_response(&response, &config.hosts[0], 3600).unwrap();
        response.principals.push("root".into());
        assert!(validate_response(&response, &config.hosts[0], 3600).is_err());
        response.principals.pop();
        response.valid_before = now - 1;
        assert!(validate_response(&response, &config.hosts[0], 3600).is_err());
    }
    #[tokio::test]
    async fn private_marker_requires_nonce_and_ack() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ready.sock");
        let prepared = Prepared {
            listener: UnixListener::bind(&socket).unwrap(),
            dir,
            nonce: "secret".into(),
            certificate_id: "test".into(),
        };
        let helper = tokio::task::spawn_blocking(move || notify(&socket, "secret"));
        let stream = prepared.marker().await.unwrap();
        assert!(!helper.is_finished());
        release(stream).await.unwrap();
        helper.await.unwrap().unwrap();
    }
    #[test]
    fn file_transport_requests_only_sftp_without_pty() {
        let config: Config = toml::from_str(include_str!("../examples/bastion.toml")).unwrap();
        let cmd = ssh_command(
            &config,
            &config.hosts[0],
            "fixture",
            Path::new("/tmp/session"),
            "nonce",
            true,
            false,
        )
        .unwrap();
        let args = cmd
            .get_argv()
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(args.iter().any(|a| a == "-T"));
        assert!(args.iter().any(|a| a == "-s"));
        assert!(!args.iter().any(|a| a == "-tt"));
        assert_eq!(args.last().unwrap(), "sftp");
        for option in [
            "StrictHostKeyChecking=yes",
            "IdentityAgent=none",
            "PasswordAuthentication=no",
            "ClearAllForwardings=yes",
        ] {
            assert!(args.iter().any(|a| a == option));
        }
    }
    #[test]
    fn sudo_file_transport_is_opt_in_and_forces_no_password_and_read_only() {
        let mut config: Config = toml::from_str(include_str!("../examples/bastion.toml")).unwrap();
        assert!(
            ssh_command(
                &config,
                &config.hosts[0],
                "mares",
                Path::new("/tmp/session"),
                "nonce",
                true,
                true
            )
            .is_err()
        );
        config.hosts[0].sftp_sudo_readonly = true;
        config.validate().unwrap();
        let cmd = ssh_command(
            &config,
            &config.hosts[0],
            "mares",
            Path::new("/tmp/session"),
            "nonce",
            true,
            true,
        )
        .unwrap();
        let args = cmd
            .get_argv()
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(!args.iter().any(|a| a == "-s" || a == "-tt"));
        assert_eq!(
            &args[args.len() - 5..],
            [
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/lib/openssh/sftp-server",
                "-R"
            ]
        );
        config.hosts[0].sftp_server = "/tmp/server;id".into();
        assert!(config.validate().is_err());
    }
}
