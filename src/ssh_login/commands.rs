use super::{
    cert_checker, keypair, oidc_browser, oidc_device, signer_client, SshLoginConfig,
};
use std::fs;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub async fn login(config: &SshLoginConfig, force_browser: bool, force_device: bool) -> Result<(), String> {
    println!("🔑 Simple IDM SSH Login");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Ensure SSH keypair exists
    keypair::ensure_keypair(&config.ssh_key_path)?;

    // Read public key
    let public_key = keypair::read_public_key(&config.public_key_path())?;

    // Get ID token via OIDC
    let id_token = if force_device {
        // Force device flow
        oidc_device::device_flow(
            &config.oidc_issuer,
            &config.client_id,
            &config.scopes,
        )
        .await?
    } else if force_browser {
        // Force browser flow
        oidc_browser::browser_flow(
            &config.oidc_issuer,
            &config.client_id,
            &config.scopes,
        )
        .await?
    } else {
        // Smart mode: try browser, fallback to device
        println!("Attempting browser flow (use --device to skip)...\n");

        match oidc_browser::browser_flow(
            &config.oidc_issuer,
            &config.client_id,
            &config.scopes,
        )
        .await
        {
            Ok(token) => token,
            Err(e) => {
                tracing::warn!("Browser flow failed: {}. Falling back to device flow.", e);
                println!("\n⚠️  Browser flow unavailable. Switching to device flow...\n");

                oidc_device::device_flow(
                    &config.oidc_issuer,
                    &config.client_id,
                    &config.scopes,
                )
                .await?
            }
        }
    };

    // Request certificate from signer
    println!("\n📜 Requesting SSH certificate...");
    let cert_info = signer_client::request_certificate(
        &config.signer_url,
        &id_token,
        &public_key,
        Some(config.ttl_seconds),
    )
    .await?;

    // Save certificate
    cert_info.save_to_file(&config.cert_path())?;

    // Display success
    println!("\n✅ SSH certificate obtained successfully!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Certificate: {:?}", config.cert_path());
    println!("Principals: {}", cert_info.principals.join(", "));
    println!("Valid for: {} seconds ({} hours)",
        cert_info.validity_duration_secs(),
        cert_info.validity_duration_secs() / 3600
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("You can now SSH to servers. Example:");
    println!("  ssh your-server.com\n");
    println!("To add to SSH config, run:");
    println!("  simple-idm-ssh-login print-ssh-config\n");

    Ok(())
}

pub fn status(config: &SshLoginConfig) -> Result<(), String> {
    let cert_path = config.cert_path();

    if !cert_path.exists() {
        println!("❌ No certificate found at {:?}", cert_path);
        println!("\nRun 'simple-idm-ssh-login login' to obtain a certificate.");
        return Ok(());
    }

    // Use ssh-keygen to inspect certificate
    let output = Command::new("ssh-keygen")
        .arg("-L")
        .arg("-f")
        .arg(&cert_path)
        .output()
        .map_err(|e| format!("Failed to run ssh-keygen: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to inspect certificate: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let cert_info = String::from_utf8_lossy(&output.stdout);

    println!("📜 SSH Certificate Status");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("{}", cert_info);

    Ok(())
}

pub fn logout(config: &SshLoginConfig) -> Result<(), String> {
    let cert_path = config.cert_path();

    if cert_path.exists() {
        fs::remove_file(&cert_path)
            .map_err(|e| format!("Failed to remove certificate: {}", e))?;
        println!("✅ Certificate removed: {:?}", cert_path);
    } else {
        println!("ℹ️  No certificate found (already logged out)");
    }

    Ok(())
}

pub fn print_ssh_config(config: &SshLoginConfig) {
    let key_path = config.ssh_key_path.clone();
    let cert_path = config.cert_path();

    println!("\n# Add this to your ~/.ssh/config:\n");
    println!("Host *.corp *.example.com");
    println!("  IdentityFile {}", key_path.display());
    println!("  CertificateFile {}", cert_path.display());
    println!("  IdentitiesOnly yes");
    println!("\n# Adjust Host patterns to match your environment");
}

/// SSH s automatickým obnovením certifikátu
pub async fn ssh(
    config: &SshLoginConfig,
    ssh_args: Vec<String>,
    force_browser: bool,
    force_device: bool,
) -> Result<(), String> {
    let cert_path = config.cert_path();

    // Zkontroluj platnost certifikátu
    let needs_renewal = if let Ok(cert_info) = cert_checker::get_certificate_info(&cert_path) {
        if cert_info.is_valid() {
            let remaining = cert_info.remaining_seconds();
            println!("✅ Certificate valid for {} seconds", remaining);
            false
        } else {
            println!("⚠️  Certificate expired");
            true
        }
    } else {
        println!("⚠️  No valid certificate found");
        true
    };

    // Obnov certifikát, pokud je potřeba
    if needs_renewal {
        println!("\n🔄 Renewing certificate...\n");
        login(config, force_browser, force_device).await?;
    }

    // Spusť SSH s certifikátem
    println!("\n🔌 Connecting via SSH...\n");

    let key_path = config.ssh_key_path.clone();

    let err = Command::new("ssh")
        .arg("-i")
        .arg(&key_path)
        .args(&ssh_args)
        .exec(); // exec() nahradí current process → nikdy se nevrátí pokud uspěje

    // Pokud jsme se dostali sem, exec() selhal
    Err(format!("Failed to execute ssh: {}", err))
}
