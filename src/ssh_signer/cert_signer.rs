use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

pub struct CertSigner {
    ca_private_key_path: PathBuf,
    default_ttl_seconds: u64,
    max_ttl_seconds: u64,
    clock_skew_seconds: u64,
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
            default_ttl_seconds,
            max_ttl_seconds,
            clock_skew_seconds,
        })
    }

    pub fn sign_certificate(&self, req: SignRequest) -> Result<SignedCert, String> {
        // Validate public key format
        self.validate_public_key(&req.public_key)?;

        // Clamp TTL
        let ttl = req
            .ttl_seconds
            .unwrap_or(self.default_ttl_seconds)
            .min(self.max_ttl_seconds);

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
        let validity = format!("+{}s", ttl);

        // Call ssh-keygen
        tracing::debug!(
            "Signing certificate: principals={:?}, ttl={}s",
            req.principals,
            ttl
        );

        let output = Command::new("ssh-keygen")
            .arg("-s")
            .arg(&self.ca_private_key_path)
            .arg("-I")
            .arg("simple-idm-cert") // Key ID
            .arg("-n")
            .arg(&principals_csv)
            .arg("-V")
            .arg(&validity)
            .arg("-z")
            .arg("1") // Serial number (TODO: increment)
            .arg(&pubkey_path)
            .output()
            .map_err(|e| format!("Failed to execute ssh-keygen: {}", e))?;

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
        // Basic validation: must start with ssh-rsa, ssh-ed25519, ecdsa-sha2-*, etc.
        let valid_prefixes = [
            "ssh-rsa",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ];

        let has_valid_prefix = valid_prefixes.iter().any(|prefix| pubkey.starts_with(prefix));

        if !has_valid_prefix {
            return Err("Invalid public key format (unsupported key type)".to_string());
        }

        // Must contain at least 2 space-separated parts (type + key)
        let parts: Vec<&str> = pubkey.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("Invalid public key format (missing key data)".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_public_key_valid() {
        let ca_key = NamedTempFile::new().expect("create temp ca key");
        let signer = CertSigner::new(
            ca_key.path().to_path_buf(),
            3600,
            28800,
            30,
        )
        .ok();

        // Ed25519 example
        let valid_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyDataHere user@host";
        assert!(signer.as_ref().unwrap().validate_public_key(valid_key).is_ok());

        // RSA example
        let rsa_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host";
        assert!(signer.as_ref().unwrap().validate_public_key(rsa_key).is_ok());
    }

    #[test]
    fn test_validate_public_key_invalid() {
        let ca_key = NamedTempFile::new().expect("create temp ca key");
        let signer = CertSigner::new(ca_key.path().to_path_buf(), 3600, 28800, 30).ok();

        // Missing key data
        assert!(signer.as_ref().unwrap().validate_public_key("ssh-ed25519").is_err());

        // Invalid prefix
        assert!(signer
            .as_ref()
            .unwrap()
            .validate_public_key("invalid-key AAAAC3...")
            .is_err());

        // Empty
        assert!(signer.as_ref().unwrap().validate_public_key("").is_err());
    }
}
