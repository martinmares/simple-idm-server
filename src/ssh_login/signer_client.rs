use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize)]
struct SignRequest {
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SignResponse {
    certificate: String,
    valid_after: i64,
    valid_before: i64,
    principals: Vec<String>,
}

pub async fn request_certificate(
    signer_url: &str,
    id_token: &str,
    public_key: &str,
    ttl_seconds: Option<u64>,
) -> Result<CertificateInfo, String> {
    let http_client = reqwest::Client::new();

    let sign_request = SignRequest {
        public_key: public_key.to_string(),
        ttl_seconds,
    };

    let sign_url = format!("{}/ssh/sign", signer_url);
    tracing::info!("Requesting certificate from {}", sign_url);

    let response = http_client
        .post(&sign_url)
        .header("Authorization", format!("Bearer {}", id_token))
        .json(&sign_request)
        .send()
        .await
        .map_err(|e| format!("Failed to request certificate: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Certificate request failed ({}): {}", status, error_text));
    }

    let sign_response: SignResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse certificate response: {}", e))?;

    Ok(CertificateInfo {
        certificate: sign_response.certificate,
        valid_after: sign_response.valid_after,
        valid_before: sign_response.valid_before,
        principals: sign_response.principals,
    })
}

#[derive(Debug)]
pub struct CertificateInfo {
    pub certificate: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub principals: Vec<String>,
}

impl CertificateInfo {
    pub fn save_to_file(&self, cert_path: &Path) -> Result<(), String> {
        // Ensure parent directory exists
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create certificate directory: {}", e))?;
        }

        fs::write(cert_path, &self.certificate)
            .map_err(|e| format!("Failed to write certificate: {}", e))?;

        tracing::info!("Certificate saved to {:?}", cert_path);
        Ok(())
    }

    pub fn validity_duration_secs(&self) -> i64 {
        self.valid_before - self.valid_after
    }

    pub fn time_until_expiry_secs(&self) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        self.valid_before - now
    }

    pub fn is_expired(&self) -> bool {
        self.time_until_expiry_secs() <= 0
    }
}
