use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};

#[derive(Clone)]
pub struct SecurityHeadersConfig {
    pub app_env: String,
    pub trust_proxy_headers: bool,
}

fn request_is_https(req: &Request, trust_proxy_headers: bool) -> bool {
    if !trust_proxy_headers {
        return false;
    }
    req.headers()
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

pub async fn security_headers_middleware(
    State(cfg): State<SecurityHeadersConfig>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let is_https = request_is_https(&req, cfg.trust_proxy_headers);

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );

    if is_https && matches!(cfg.app_env.as_str(), "prod" | "production") {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    Ok(resp)
}
