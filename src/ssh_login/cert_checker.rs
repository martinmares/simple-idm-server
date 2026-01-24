use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use std::path::Path;
use std::process::Command;

fn parse_sshkeygen_local_datetime(s: &str) -> Result<DateTime<Utc>, String> {
    // ssh-keygen tiskne bez timezone, ale je to lokální čas stroje
    let naive = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .map_err(|e| format!("Failed to parse local datetime '{}': {}", s, e))?;

    let local_dt = Local
        .from_local_datetime(&naive)
        .single()
        .ok_or_else(|| format!("Ambiguous or invalid local datetime '{}'", s))?;

    Ok(local_dt.with_timezone(&Utc))
}

/// Zkontroluje platnost SSH certifikátu
pub fn is_certificate_valid(cert_path: &Path) -> Result<bool, String> {
    if !cert_path.exists() {
        return Ok(false);
    }

    // Spusť ssh-keygen -L -f cert.pub
    let output = Command::new("ssh-keygen")
        .arg("-L")
        .arg("-f")
        .arg(cert_path)
        .output()
        .map_err(|e| format!("Failed to run ssh-keygen: {}", e))?;

    if !output.status.success() {
        return Ok(false); // Certifikát neexistuje nebo je poškozený
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse "Valid: from YYYY-MM-DDTHH:MM:SS to YYYY-MM-DDTHH:MM:SS"
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Valid:") {
            return parse_validity(trimmed);
        }
    }

    Ok(false) // Nenašli jsme Valid: řádek
}

fn parse_validity(line: &str) -> Result<bool, String> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if let Some(to_idx) = parts.iter().position(|&s| s == "to") {
        if let Some(expiry_str) = parts.get(to_idx + 1) {
            let expiry_utc = parse_sshkeygen_local_datetime(expiry_str)?;
            return Ok(expiry_utc > Utc::now());
        }
    }

    Err("Could not parse certificate validity".to_string())
}

/// Získá informace o zbývající platnosti certifikátu
pub fn get_certificate_info(cert_path: &Path) -> Result<CertificateInfo, String> {
    if !cert_path.exists() {
        return Err("Certificate does not exist".to_string());
    }

    let output = Command::new("ssh-keygen")
        .arg("-L")
        .arg("-f")
        .arg(cert_path)
        .output()
        .map_err(|e| format!("Failed to run ssh-keygen: {}", e))?;

    if !output.status.success() {
        return Err("Invalid certificate".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut valid_from = None;
    let mut valid_to = None;
    let mut principals = Vec::new();

    let mut in_principals_section = false;

    for line in stdout.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Valid:") {
            // Parse "Valid: from YYYY-MM-DDTHH:MM:SS to YYYY-MM-DDTHH:MM:SS"
            let parts: Vec<&str> = trimmed.split_whitespace().collect();

            if let Some(from_idx) = parts.iter().position(|&s| s == "from") {
                if let Some(from_str) = parts.get(from_idx + 1) {
                    valid_from = Some(parse_sshkeygen_local_datetime(from_str)?);
                }
            }

            if let Some(to_idx) = parts.iter().position(|&s| s == "to") {
                if let Some(to_str) = parts.get(to_idx + 1) {
                    valid_to = Some(parse_sshkeygen_local_datetime(to_str)?);
                }
            }
        } else if trimmed.starts_with("Principals:") {
            in_principals_section = true;
        } else if in_principals_section {
            if trimmed.is_empty() || trimmed.starts_with("Critical Options:") {
                in_principals_section = false;
            } else {
                principals.push(trimmed.to_string());
            }
        }
    }

    match (valid_from, valid_to) {
        (Some(from), Some(to)) => Ok(CertificateInfo {
            valid_from: from,
            valid_to: to,
            principals,
        }),
        _ => Err("Could not parse certificate validity".to_string()),
    }
}

#[derive(Debug)]
pub struct CertificateInfo {
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub principals: Vec<String>,
}

impl CertificateInfo {
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.valid_from && now < self.valid_to
    }

    pub fn remaining_seconds(&self) -> i64 {
        let now = Utc::now();
        (self.valid_to - now).num_seconds()
    }
}
