//! Local configuration editing; never restarts the daemon or changes remote hosts.
use crate::config::{Config, Host};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use fs2::FileExt;
use std::{
    fs,
    io::{self, IsTerminal, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Args)]
pub struct AddHost {
    /// Unique host ID (prompted when omitted).
    #[arg(long, required_if_eq("yes", "true"))]
    pub id: Option<String>,
    /// Name displayed in the host list.
    #[arg(long, required_if_eq("yes", "true"))]
    pub name: Option<String>,
    /// Hostname or IP reachable from the bastion.
    #[arg(long, required_if_eq("yes", "true"))]
    pub address: Option<String>,
    #[arg(long, default_value_t = 22)]
    pub port: u16,
    /// Environment label, such as infra or production.
    #[arg(long, required_if_eq("yes", "true"))]
    pub environment: Option<String>,
    /// Optional host description.
    #[arg(long)]
    pub description: Option<String>,
    /// Repeat or use commas for multiple permitted IDM groups.
    #[arg(long = "group", value_delimiter = ',', required_if_eq("yes", "true"))]
    pub groups: Vec<String>,
    /// Repeat or use commas for multiple Linux logins; {username} is supported.
    #[arg(long = "login", value_delimiter = ',', required_if_eq("yes", "true"))]
    pub logins: Vec<String>,
    /// Optional narrowing of signer-authorized certificate principals.
    #[arg(long = "principal", value_delimiter = ',')]
    pub principals: Vec<String>,
    /// Independently verified SHA256 fingerprint of the host's ED25519 key.
    /// Paste only SHA256:... (the second field of ssh-keygen output), not the full line.
    /// Fetch and pin that key in configured known_hosts before saving the host.
    #[arg(long)]
    pub host_key_fingerprint: Option<String>,
    /// Validate and show the change without writing files or scanning host keys.
    #[arg(long)]
    pub dry_run: bool,
    /// Save without confirmation. All required fields must be provided.
    #[arg(long)]
    pub yes: bool,
}

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    print!(
        "{label}{}: ",
        default.map(|d| format!(" [{d}]")).unwrap_or_default()
    );
    io::stdout().flush()?;
    let mut value = String::new();
    ensure!(
        io::stdin().read_line(&mut value)? > 0,
        "input closed; nothing saved"
    );
    let value = value.trim();
    Ok(if value.is_empty() {
        default.unwrap_or_default().to_owned()
    } else {
        value.to_owned()
    })
}
fn required(value: Option<String>, label: &str, interactive: bool) -> Result<String> {
    let value = match value {
        Some(value) => value,
        None if interactive => prompt(label, None)?,
        None => bail!("missing {label}; provide all required arguments with --yes"),
    };
    ensure!(!value.trim().is_empty(), "{label} cannot be empty");
    Ok(value)
}
fn list(values: Vec<String>, label: &str, interactive: bool) -> Result<Vec<String>> {
    let values = if values.is_empty() && interactive {
        prompt(label, None)?
            .split(',')
            .map(|s| s.trim().to_owned())
            .collect()
    } else {
        values
    };
    ensure!(
        !values.is_empty() && values.iter().all(|s| !s.trim().is_empty()),
        "{label} required"
    );
    Ok(values)
}

/// Append instead of reserializing the document: existing comments/layout survive.
fn candidate(original: &str, host: &Host) -> Result<(String, String)> {
    let block = format!("\n[[hosts]]\n{}", toml::to_string_pretty(host)?);
    let document = format!("{}{block}", original.trim_end_matches('\n'));
    let config: Config = toml::from_str(&document)?;
    config.validate()?;
    Ok((document, block))
}

/// Preserve permissions, retain an exclusive backup, then replace atomically.
fn replace(path: &Path, original: &[u8], content: &[u8]) -> Result<PathBuf> {
    ensure!(
        fs::read(path)? == original,
        "{} changed during editing; nothing overwritten",
        path.display()
    );
    let parent = path.parent().context("file parent required")?;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    let mut backup = tempfile::NamedTempFile::new_in(parent)?;
    backup
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    backup.write_all(original)?;
    backup.as_file().sync_all()?;
    let backup_path = path.with_file_name(format!(
        "{}.bak-{}",
        path.file_name()
            .context("filename required")?
            .to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    backup.persist_noclobber(&backup_path)?;
    let mut next = tempfile::NamedTempFile::new_in(parent)?;
    next.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    next.write_all(content)?;
    next.as_file().sync_all()?;
    ensure!(
        fs::read(path)? == original,
        "file changed during editing; backup kept at {}",
        backup_path.display()
    );
    next.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(backup_path)
}

fn verified_key(host: &Host, expected: &str) -> Result<String> {
    ensure!(
        expected.starts_with("SHA256:") && !expected.contains(char::is_whitespace),
        "expected SHA256:<fingerprint>"
    );
    let output = Command::new("ssh-keyscan")
        .args([
            "-T",
            "5",
            "-t",
            "ed25519",
            "-p",
            &host.port.to_string(),
            &host.address,
        ])
        .output()
        .context("run ssh-keyscan")?;
    ensure!(
        output.status.success(),
        "ssh-keyscan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let keys = String::from_utf8(output.stdout)?;
    let mut verified = Vec::new();
    for line in keys
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(
            fields.len() == 3 && fields[1] == "ssh-ed25519",
            "unexpected scanned key format"
        );
        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(file, "{line}")?;
        file.flush()?;
        let result = Command::new("ssh-keygen")
            .args(["-E", "sha256", "-lf"])
            .arg(file.path())
            .output()?;
        ensure!(result.status.success(), "cannot fingerprint scanned key");
        let result = String::from_utf8(result.stdout)?;
        ensure!(
            result.split_whitespace().nth(1) == Some(expected),
            "host key fingerprint mismatch; nothing saved"
        );
        verified.push(line.to_owned());
    }
    ensure!(
        !verified.is_empty(),
        "no ED25519 key received; nothing saved"
    );
    Ok(verified.join("\n") + "\n")
}

pub fn run(path: &Path, args: AddHost) -> Result<()> {
    let interactive = !args.yes && io::stdin().is_terminal() && io::stdout().is_terminal();
    let path = fs::canonicalize(path).context("existing config file required")?;
    let lock_path = path.with_file_name(format!(
        "{}.edit.lock",
        path.file_name().unwrap().to_string_lossy()
    ));
    // Separate lock survives atomic replacement. It does not conflict with the running daemon.
    let _lock = if args.dry_run {
        None
    } else {
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)?;
        lock.try_lock_exclusive()
            .context("another configuration editor is running")?;
        Some(lock)
    };
    let original = fs::read_to_string(&path)?;
    let config: Config = toml::from_str(&original)?;
    config.validate()?;
    if interactive {
        println!(
            "Add a host to {}\nNo service restart will be performed.\n",
            path.display()
        );
    }
    let host = Host {
        id: required(args.id, "host ID (--id)", interactive)?,
        name: required(args.name, "display name (--name)", interactive)?,
        address: required(args.address, "hostname/IP (--address)", interactive)?,
        port: if interactive {
            prompt("SSH port", Some(&args.port.to_string()))?
                .parse()
                .context("invalid port")?
        } else {
            args.port
        },
        environment: required(args.environment, "environment (--environment)", interactive)?,
        description: match args.description {
            Some(value) => value,
            None if interactive => prompt("Description (optional)", None)?,
            None => String::new(),
        },
        allowed_groups: list(
            args.groups,
            "IDM groups, comma separated (--group)",
            interactive,
        )?,
        logins: list(
            args.logins,
            "Linux logins, comma separated (--login)",
            interactive,
        )?,
        principals: if args.principals.is_empty() && interactive {
            let value = prompt("Certificate principals (optional, comma separated)", None)?;
            if value.is_empty() {
                None
            } else {
                Some(value.split(',').map(|s| s.trim().to_owned()).collect())
            }
        } else if args.principals.is_empty() {
            None
        } else {
            Some(args.principals)
        },
    };
    let (document, block) = candidate(&original, &host)?;
    println!("\nValidated addition:\n{block}");
    if args.dry_run {
        println!("Dry run: no config or known_hosts changes; no key scan.");
        return Ok(());
    }
    let fingerprint = match args.host_key_fingerprint {
        Some(value) => Some(value),
        None if interactive => {
            println!(
                "Obtain the fingerprint on the TARGET host '{}':\n  sudo ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub\n\nExample output:\n  256 SHA256:ZudzRznJG5nvUqgei4Ef4Nn9j0VhxbW2iHrsnKo3TgY root@target (ED25519)\n\nPaste ONLY the second field, including SHA256:, for example:\n  SHA256:ZudzRznJG5nvUqgei4Ef4Nn9j0VhxbW2iHrsnKo3TgY\nDo not paste 256, root@target or (ED25519). Use your target's fingerprint, not this example.",
                host.address
            );
            let value = prompt(
                "Paste SHA256:... only (Enter without a value = manage known_hosts manually)",
                None,
            )?;
            (!value.is_empty()).then_some(value)
        }
        None => None,
    };
    let key = fingerprint
        .as_deref()
        .map(|fingerprint| verified_key(&host, fingerprint))
        .transpose()?;
    if !args.yes {
        ensure!(
            interactive,
            "use --yes to save non-interactively, or --dry-run to preview"
        );
        if !matches!(
            prompt("Save host and any verified host key?", Some("no"))?
                .to_lowercase()
                .as_str(),
            "yes" | "y"
        ) {
            println!("Cancelled; no config or known_hosts changes.");
            return Ok(());
        }
    }
    ensure!(
        fs::read_to_string(&path)? == original,
        "config changed; nothing saved"
    );
    if let Some(key) = key {
        let known_path =
            fs::canonicalize(&config.known_hosts).context("known_hosts must already exist")?;
        ensure!(known_path != path, "known_hosts must differ from config");
        let known = fs::read_to_string(&known_path)?;
        let mut next = known.clone();
        for line in key.lines() {
            if !known.lines().any(|old| old == line) {
                if !next.is_empty() && !next.ends_with('\n') {
                    next.push('\n');
                }
                next.push_str(line);
                next.push('\n');
            }
        }
        if next != known {
            let backup = replace(&known_path, known.as_bytes(), next.as_bytes())?;
            println!(
                "Verified key saved. known_hosts backup: {}",
                backup.display()
            );
        }
    } else {
        println!(
            "Host key was not scanned: ensure an independently verified key exists in {} before connecting.",
            config.known_hosts.display()
        );
    }
    let backup = replace(&path, original.as_bytes(), document.as_bytes())?;
    println!(
        "Host '{}' saved. Config backup: {}\nRestart your service manually to load the new host. Restart ends active sessions.\nThen reopen the client host list.",
        host.id,
        backup.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn appending_preserves_comments_and_rejects_duplicate_or_invalid_hosts() {
        let original = include_str!("../examples/bastion.toml");
        let mut host = Host {
            id: "new-host".into(),
            name: "New host".into(),
            address: "nuc.cluster".into(),
            port: 22,
            environment: "infra".into(),
            description: "Quotes \" and newline\n".into(),
            allowed_groups: vec!["ssh:principal:mares".into()],
            logins: vec!["mares".into()],
            principals: None,
        };
        let (next, _) = candidate(original, &host).unwrap();
        assert!(next.starts_with(original.trim_end_matches('\n')));
        let c: Config = toml::from_str(&next).unwrap();
        assert_eq!(c.hosts.last().unwrap().description, host.description);
        assert!(candidate(&next, &host).is_err());
        host.id = "other".into();
        host.address = "-oProxyCommand=evil".into();
        assert!(candidate(original, &host).is_err());
    }
    #[test]
    fn atomic_save_keeps_backup_permissions_and_detects_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let backup = replace(&path, b"original", b"updated").unwrap();
        assert_eq!(fs::read_to_string(&backup).unwrap(), "original");
        assert_eq!(fs::read_to_string(&path).unwrap(), "updated");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(replace(&path, b"original", b"lost edit").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "updated");
    }
}
