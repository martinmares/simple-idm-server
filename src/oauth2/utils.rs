use axum::http::{header, HeaderMap};
use base64::Engine as _;

/// Check if client is public (no client_secret required)
/// Public client has NULL client_secret_hash in database
#[allow(dead_code)]
pub fn is_public_client(client_secret_hash: &Option<String>) -> bool {
    client_secret_hash.is_none()
}

pub fn apply_client_auth(
    client_id: &mut Option<String>,
    client_secret: &mut Option<String>,
    headers: &HeaderMap,
) {
    if let Some((basic_id, basic_secret)) = parse_basic_auth(headers) {
        if client_id.as_deref().unwrap_or("").is_empty() {
            *client_id = Some(basic_id);
        }
        if client_secret.as_deref().unwrap_or("").is_empty() {
            *client_secret = Some(basic_secret);
        }
    }

    if client_id
        .as_deref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(false)
    {
        *client_id = None;
    }
    if client_secret
        .as_deref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(false)
    {
        *client_secret = None;
    }
}

pub fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let header_value = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?;

    if !header_value.to_ascii_lowercase().starts_with("basic ") {
        return None;
    }

    let encoded = header_value.split_at(6).1;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;

    let mut parts = decoded.splitn(2, ':');
    let client_id = parts.next()?.to_string();
    let client_secret = parts.next()?.to_string();
    Some((client_id, client_secret))
}
