use std::fs;
use std::path::Path;
use std::process::Command;

/// Ensure SSH keypair exists. Generate Ed25519 if missing.
/// Returns path to public key.
pub fn ensure_keypair(private_key_path: &Path) -> Result<(), String> {
    if private_key_path.exists() {
        tracing::info!("Using existing SSH key: {:?}", private_key_path);
        return Ok(());
    }

    tracing::info!("Generating new Ed25519 SSH keypair at {:?}", private_key_path);

    // Ensure parent directory exists
    if let Some(parent) = private_key_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create SSH directory: {}", e))?;
    }

    // Generate Ed25519 key
    let output = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-f")
        .arg(private_key_path)
        .arg("-N")
        .arg("") // No passphrase
        .arg("-C")
        .arg("simple-idm-ssh-login")
        .output()
        .map_err(|e| format!("Failed to run ssh-keygen: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    tracing::info!("SSH keypair generated successfully");
    Ok(())
}

/// Read public key from file
pub fn read_public_key(public_key_path: &Path) -> Result<String, String> {
    if !public_key_path.exists() {
        return Err(format!("Public key not found: {:?}", public_key_path));
    }

    fs::read_to_string(public_key_path)
        .map_err(|e| format!("Failed to read public key: {}", e))
        .map(|s| s.trim().to_string())
}
