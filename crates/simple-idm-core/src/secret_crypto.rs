use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::Rng;
use regex::Regex;
use std::sync::OnceLock;

const API_VERSION: &str = "2.0";
const ENC_PREFIX_NEW: &str = "EncSimple";
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const MAC_LEN: usize = 16;

static MASTER_KEY: OnceLock<[u8; KEY_LEN]> = OnceLock::new();

fn load_master_key() -> Result<[u8; KEY_LEN]> {
    let raw =
        std::env::var("IDP_SECRETS_MASTER_KEY").context("IDP_SECRETS_MASTER_KEY is not set")?;

    if let Ok(bytes) = B64.decode(raw.trim()) {
        if bytes.len() == KEY_LEN {
            let mut out = [0u8; KEY_LEN];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }

    if raw.len() == KEY_LEN {
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(raw.as_bytes());
        return Ok(out);
    }

    Err(anyhow!(
        "IDP_SECRETS_MASTER_KEY must be base64(32 bytes) or 32-char raw key"
    ))
}

fn key() -> Result<&'static [u8; KEY_LEN]> {
    if let Some(v) = MASTER_KEY.get() {
        return Ok(v);
    }
    let loaded = load_master_key()?;
    let _ = MASTER_KEY.set(loaded);
    MASTER_KEY
        .get()
        .ok_or_else(|| anyhow!("Failed to initialize master key"))
}

/// Validate that encrypted identity and TOTP secrets can be created.
pub fn validate_master_key() -> Result<()> {
    key().map(|_| ())
}

fn is_encrypted(val: &str) -> bool {
    static ENC_RE: OnceLock<Regex> = OnceLock::new();
    ENC_RE
        .get_or_init(|| Regex::new(r"(?i)^EncSimple\[@api=(.*):@box=(.*)\]$").expect("valid regex"))
        .is_match(val)
}

fn extract_box(val: &str) -> &str {
    static ENC_RE: OnceLock<Regex> = OnceLock::new();
    ENC_RE
        .get_or_init(|| Regex::new(r"(?i)^EncSimple\[@api=(.*):@box=(.*)\]$").expect("valid regex"))
        .captures(val)
        .and_then(|cap| cap.get(2))
        .map(|m| m.as_str())
        .unwrap_or(val)
}

pub fn encrypt_secret(plaintext: &str) -> Result<String> {
    if is_encrypted(plaintext) {
        return Ok(plaintext.to_string());
    }
    encrypt_secret_with_key(plaintext, key()?)
}

fn encrypt_secret_with_key(plaintext: &str, key: &[u8; KEY_LEN]) -> Result<String> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("Invalid encryption key material"))?;
    let nonce = XNonce::from(nonce_bytes);
    let ct_and_tag = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow!("Encryption failed"))?;

    if ct_and_tag.len() < MAC_LEN {
        return Err(anyhow!("Encryption output too short"));
    }

    let mut out = Vec::with_capacity(NONCE_LEN + ct_and_tag.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct_and_tag);
    Ok(format!(
        "{}[@api={}:@box={}]",
        ENC_PREFIX_NEW,
        API_VERSION,
        B64.encode(out)
    ))
}

pub fn decrypt_secret(stored: &str) -> Result<String> {
    if !is_encrypted(stored) {
        return Err(anyhow!(
            "Secret must use EncSimple[@api=...:@box=...] format"
        ));
    }
    decrypt_secret_with_key(stored, key()?)
}

fn decrypt_secret_with_key(stored: &str, key: &[u8; KEY_LEN]) -> Result<String> {
    let box_b64 = extract_box(stored);
    let bytes = B64
        .decode(box_b64)
        .context("Invalid encrypted secret payload")?;

    if bytes.len() < NONCE_LEN + MAC_LEN {
        return Err(anyhow!("Encrypted secret too short (nonce+ciphertext+tag)"));
    }

    let nonce = XNonce::try_from(&bytes[..NONCE_LEN])
        .map_err(|_| anyhow!("Invalid encrypted secret nonce"))?;
    let ct_and_tag = &bytes[NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("Invalid encryption key material"))?;
    let plain = cipher
        .decrypt(&nonce, ct_and_tag)
        .map_err(|_| anyhow!("Secret decryption failed"))?;
    String::from_utf8(plain).context("Decrypted secret is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_secret_from_chacha20poly1305_0_10() {
        // Generated with chacha20poly1305 0.10.1 using a test-only key.
        let stored = "EncSimple[@api=2.0:@box=JCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkyTuwBA1dYdbQQElTau1/50GU7cgZa4KUAovDhVVLJ6sRGfs3MEc=]";
        assert_eq!(
            decrypt_secret_with_key(stored, &[0x42; KEY_LEN]).unwrap(),
            "legacy-provider-secret"
        );
        assert!(decrypt_secret_with_key(stored, &[0x43; KEY_LEN]).is_err());
    }

    #[test]
    fn secret_roundtrip_rejects_tampering_and_uses_random_nonces() {
        let key = [0x42; KEY_LEN];
        let first = encrypt_secret_with_key("test-secret", &key).unwrap();
        let second = encrypt_secret_with_key("test-secret", &key).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            decrypt_secret_with_key(&first, &key).unwrap(),
            "test-secret"
        );
        let mut bytes = B64.decode(extract_box(&first)).unwrap();
        bytes[NONCE_LEN] ^= 1;
        let altered = format!("EncSimple[@api=2.0:@box={}]", B64.encode(bytes));
        assert!(decrypt_secret_with_key(&altered, &key).is_err());
        assert!(decrypt_secret("plaintext").is_err());
    }
}
