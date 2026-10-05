use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

pub struct CertSigner {
    ca_private_key_path: PathBuf,
    cert_key_id: String,
    default_ttl_seconds: u64,
    max_ttl_seconds: u64,
    clock_skew_seconds: u64,
    extensions: Vec<&'static str>,
}

pub struct SignRequest {
    pub public_key: String,
    pub principals: Vec<String>,
    pub ttl_seconds: Option<u64>,
}

pub struct SignedCert {
    pub certificate: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub principals: Vec<String>,
}

impl CertSigner {
    pub fn new(
        ca_private_key_path: PathBuf,
        cert_key_id: String,
        default_ttl_seconds: u64,
        max_ttl_seconds: u64,
        clock_skew_seconds: u64,
    ) -> Result<Self, String> {
        if !ca_private_key_path.exists() {
            return Err(format!(
                "CA private key not found: {:?}",
                ca_private_key_path
            ));
        }

        Ok(Self {
            ca_private_key_path,
            cert_key_id,
            default_ttl_seconds,
            max_ttl_seconds,
            clock_skew_seconds,
            extensions: vec!["permit-pty"],
        })
    }

    pub fn with_extensions(mut self, config: &super::config::SshSignerConfig) -> Self {
        for (enabled, extension) in [
            (config.permit_port_forwarding, "permit-port-forwarding"),
            (config.permit_agent_forwarding, "permit-agent-forwarding"),
            (config.permit_x11_forwarding, "permit-X11-forwarding"),
            (config.permit_user_rc, "permit-user-rc"),
        ] {
            if enabled {
                self.extensions.push(extension);
            }
        }
        self
    }

    pub fn sign_certificate(&self, req: SignRequest) -> Result<SignedCert, String> {
        self.sign_with_identity(req, &self.cert_key_id, false)
    }

    pub fn sign_bastion_certificate(
        &self,
        req: SignRequest,
        session_id: &str,
    ) -> Result<SignedCert, String> {
        let session_id = uuid::Uuid::parse_str(session_id).map_err(|_| "Invalid session ID")?;
        self.sign_with_identity(
            req,
            &format!("{}:bastion:{}", self.cert_key_id, session_id),
            true,
        )
    }

    fn sign_with_identity(
        &self,
        req: SignRequest,
        identity: &str,
        bastion: bool,
    ) -> Result<SignedCert, String> {
        // Validate public key format
        self.validate_public_key(&req.public_key)?;

        // Clamp TTL
        let ttl = req
            .ttl_seconds
            .unwrap_or(self.default_ttl_seconds)
            .min(self.max_ttl_seconds);
        if ttl == 0 || req.principals.is_empty() {
            return Err("Nonzero TTL and principals required".into());
        }

        // Calculate validity period
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let valid_after = now - self.clock_skew_seconds as i64;
        let valid_before = now + ttl as i64;

        // Create temp directory
        let tmp_dir = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;

        // Write public key to temp file
        let pubkey_path = tmp_dir.path().join("user.pub");
        fs::write(&pubkey_path, &req.public_key)
            .map_err(|e| format!("Failed to write public key: {}", e))?;

        // Build principals CSV (sanitized)
        let principals_csv = req.principals.join(",");

        // Build validity string
        let validity = format!("-{}s:+{}s", self.clock_skew_seconds, ttl);

        // Call ssh-keygen
        tracing::debug!(
            "Signing certificate: principals={:?}, ttl={}s",
            req.principals,
            ttl
        );

        let serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
            .to_string();

        let mut command = Command::new("ssh-keygen");
        command
            .arg("-s")
            .arg(&self.ca_private_key_path)
            .arg("-I")
            .arg(identity)
            .arg("-n")
            .arg(&principals_csv)
            .arg("-V")
            .arg(&validity)
            .arg("-z")
            .arg(&serial);
        command.args(["-O", "clear"]);
        let extensions: &[&str] = if bastion {
            &["permit-pty"]
        } else {
            &self.extensions
        };
        for extension in extensions {
            command.args(["-O", extension]);
        }
        let mut child = command
            .arg(&pubkey_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| format!("Failed to execute ssh-keygen: {error}"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_none()
        {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("ssh-keygen exceeded signing timeout".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child
            .wait_with_output()
            .map_err(|error| error.to_string())?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("ssh-keygen failed: {}", stderr));
        }

        // Read signed certificate
        let cert_path = tmp_dir.path().join("user-cert.pub");
        let certificate = fs::read_to_string(&cert_path)
            .map_err(|e| format!("Failed to read certificate: {}", e))?;

        tracing::info!(
            "Certificate signed successfully: {} principals, valid for {}s",
            req.principals.len(),
            ttl
        );

        Ok(SignedCert {
            certificate: certificate.trim().to_string(),
            valid_after,
            valid_before,
            principals: req.principals,
        })
    }

    fn validate_public_key(&self, pubkey: &str) -> Result<(), String> {
        if pubkey.len() > 16_384 || pubkey.trim_end().contains(['\r', '\n', '\0']) {
            return Err("A single public key record of at most 16 KiB is required".into());
        }
        // Basic validation: must start with ssh-rsa, ssh-ed25519, ecdsa-sha2-*, etc.
        let valid_prefixes = [
            "ssh-rsa",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ];

        let has_valid_prefix = valid_prefixes
            .iter()
            .any(|prefix| pubkey.split_whitespace().next() == Some(*prefix));

        if !has_valid_prefix {
            return Err("Invalid public key format (unsupported key type)".to_string());
        }

        // Must contain at least 2 space-separated parts (type + key)
        let parts: Vec<&str> = pubkey.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("Invalid public key format (missing key data)".to_string());
        }

        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|_| "Invalid SSH key encoding")?;
        let mut remaining = data.as_slice();
        fn field<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], String> {
            if data.len() < 4 {
                return Err("Truncated SSH key".into());
            }
            let length = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
            *data = &data[4..];
            if length > data.len() {
                return Err("Truncated SSH key field".into());
            }
            let value = &data[..length];
            *data = &data[length..];
            Ok(value)
        }
        if field(&mut remaining)? != parts[0].as_bytes() {
            return Err("SSH key type mismatch".into());
        }
        match parts[0] {
            "ssh-ed25519" => {
                if field(&mut remaining)?.len() != 32 {
                    return Err("Invalid Ed25519 key length".into());
                }
            }
            "ssh-rsa" => {
                if field(&mut remaining)?.is_empty() || field(&mut remaining)?.len() < 256 {
                    return Err("RSA public key must be at least 2048 bits".into());
                }
            }
            curve_type => {
                let curve = curve_type
                    .strip_prefix("ecdsa-sha2-")
                    .ok_or("Invalid key type")?;
                if field(&mut remaining)? != curve.as_bytes() {
                    return Err("ECDSA curve mismatch".into());
                }
                let point = field(&mut remaining)?;
                let size = match curve {
                    "nistp256" => 65,
                    "nistp384" => 97,
                    "nistp521" => 133,
                    _ => return Err("Unsupported curve".into()),
                };
                if point.len() != size || point[0] != 4 {
                    return Err("Invalid ECDSA point".into());
                }
            }
        }
        if !remaining.is_empty() {
            return Err("Unexpected SSH key data".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn bastion_certificate_is_correlated_and_only_permits_pty() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca");
        let user = dir.path().join("user");
        for path in [&ca, &user] {
            assert!(
                Command::new("ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let signer = CertSigner::new(ca, "test-ca".into(), 3600, 3600, 30).unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        let cert = signer
            .sign_bastion_certificate(
                SignRequest {
                    public_key: fs::read_to_string(user.with_extension("pub")).unwrap(),
                    principals: vec!["alice".into()],
                    ttl_seconds: Some(3600),
                },
                &session,
            )
            .unwrap();
        let path = dir.path().join("cert.pub");
        fs::write(&path, cert.certificate).unwrap();
        let inspect = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(path)
            .output()
            .unwrap();
        assert!(inspect.status.success());
        let text = String::from_utf8(inspect.stdout).unwrap();
        assert!(text.contains(&format!("test-ca:bastion:{session}")));
        assert!(text.contains("permit-pty"));
        assert!(!text.contains("permit-port-forwarding"));
        assert!(!text.contains("permit-agent-forwarding"));
        assert!(!text.contains("permit-X11-forwarding"));
        let direct = signer
            .sign_certificate(SignRequest {
                public_key: fs::read_to_string(user.with_extension("pub")).unwrap(),
                principals: vec!["alice".into()],
                ttl_seconds: None,
            })
            .unwrap();
        let direct_path = dir.path().join("direct.pub");
        fs::write(&direct_path, direct.certificate).unwrap();
        let inspect = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(&direct_path)
            .output()
            .unwrap();
        let text = String::from_utf8(inspect.stdout).unwrap();
        for forbidden in [
            "permit-port-forwarding",
            "permit-agent-forwarding",
            "permit-X11-forwarding",
            "permit-user-rc",
        ] {
            assert!(!text.contains(forbidden));
        }
        let config = super::super::config::SshSignerConfig {
            permit_agent_forwarding: true,
            ..Default::default()
        };
        let enabled = signer
            .with_extensions(&config)
            .sign_certificate(SignRequest {
                public_key: fs::read_to_string(user.with_extension("pub")).unwrap(),
                principals: vec!["alice".into()],
                ttl_seconds: None,
            })
            .unwrap();
        fs::write(&direct_path, enabled.certificate).unwrap();
        let inspect = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(&direct_path)
            .output()
            .unwrap();
        assert!(
            String::from_utf8(inspect.stdout)
                .unwrap()
                .contains("permit-agent-forwarding")
        );
    }

    #[test]
    fn test_validate_public_key_valid() {
        let ca_key = NamedTempFile::new().expect("create temp ca key");
        let signer = CertSigner::new(
            ca_key.path().to_path_buf(),
            "simple-idm-cert".to_string(),
            3600,
            28800,
            30,
        )
        .ok();

        let dir = tempfile::tempdir().unwrap();
        for kind in ["ed25519", "rsa"] {
            let key = dir.path().join(kind);
            assert!(
                Command::new("ssh-keygen")
                    .args(["-q", "-t", kind, "-N", "", "-f"])
                    .arg(&key)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                signer
                    .as_ref()
                    .unwrap()
                    .validate_public_key(&fs::read_to_string(key.with_extension("pub")).unwrap())
                    .is_ok()
            );
        }
    }

    #[test]
    fn test_validate_public_key_invalid() {
        let ca_key = NamedTempFile::new().expect("create temp ca key");
        let signer = CertSigner::new(
            ca_key.path().to_path_buf(),
            "simple-idm-cert".to_string(),
            3600,
            28800,
            30,
        )
        .ok();

        // Missing key data
        assert!(
            signer
                .as_ref()
                .unwrap()
                .validate_public_key("ssh-ed25519")
                .is_err()
        );

        // Invalid prefix
        assert!(
            signer
                .as_ref()
                .unwrap()
                .validate_public_key("invalid-key AAAAC3...")
                .is_err()
        );

        // Empty
        assert!(signer.as_ref().unwrap().validate_public_key("").is_err());
    }
}
