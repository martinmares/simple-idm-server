/// HTML templates for OAuth2 Authorization Code Flow.
use axum::response::Html;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
struct UiBranding {
    brand_name: String,
    brand_domain: Option<String>,
    page_title: String,
}

impl Default for UiBranding {
    fn default() -> Self {
        Self {
            brand_name: "Cloud App".to_string(),
            brand_domain: None,
            page_title: "Simple IDM".to_string(),
        }
    }
}

static UI_BRANDING: OnceLock<UiBranding> = OnceLock::new();

#[allow(dead_code)]
pub fn set_branding_from_config(
    brand_name: String,
    brand_domain: Option<String>,
    page_title: String,
) {
    let _ = UI_BRANDING.set(UiBranding {
        brand_name,
        brand_domain,
        page_title,
    });
}

fn get_branding() -> &'static UiBranding {
    UI_BRANDING.get_or_init(UiBranding::default)
}

fn brand_label() -> String {
    let branding = get_branding();
    let brand_name = escape_html(&branding.brand_name);
    if let Some(domain) = &branding.brand_domain {
        format!("{} · {}", brand_name, escape_html(domain))
    } else {
        brand_name
    }
}

fn default_description() -> String {
    let branding = get_branding();
    if let Some(domain) = &branding.brand_domain {
        format!("Secure sign-in for {}.", escape_html(domain))
    } else {
        "Secure sign-in for internal dashboards and admin tools.".to_string()
    }
}

fn page_title(title: &str) -> String {
    format!(
        "{} - {}",
        escape_html(title),
        escape_html(&get_branding().page_title)
    )
}

fn user_placeholder() -> String {
    format!(
        "user@{}",
        get_branding()
            .brand_name
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .trim_matches('-')
    )
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_page(
    title: &str,
    eyebrow: &str,
    heading: &str,
    description: &str,
    body: &str,
    footer: &str,
    width_class: &str,
) -> String {
    format!(
        r#"<!doctype html>
<html lang="en" data-bs-theme="auto">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{}</title>
  <link href="/admin/ui/static/css/tabler.min.css" rel="stylesheet">
  <link href="/admin/ui/static/css/tabler-icons.min.css" rel="stylesheet">
  <script>
    (function () {{
      const t = localStorage.getItem('theme') || 'auto';
      if (t === 'auto') {{
        const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        document.documentElement.setAttribute('data-bs-theme', dark ? 'dark' : 'light');
      }} else {{
        document.documentElement.setAttribute('data-bs-theme', t);
      }}
    }})();
  </script>
</head>
<body class="d-flex align-items-center justify-content-center min-vh-100 bg-body">
  <div class="container-tight py-4 {}">
    <div class="card card-md">
      <div class="card-body">
        <div class="mb-4">
          <div class="text-secondary text-uppercase fw-semibold small mb-2">{}</div>
          <h1 class="h2 mb-2">{}</h1>
          <p class="text-secondary mb-0">{}</p>
        </div>
        {}
        <div class="mt-4 text-center text-secondary small">
          {}
        </div>
      </div>
    </div>
  </div>
</body>
</html>"#,
        page_title(title),
        width_class,
        escape_html(eyebrow),
        escape_html(heading),
        description,
        body,
        footer
    )
}

fn alert(variant: &str, message: &str) -> String {
    format!(
        r#"<div class="alert alert-{}" role="alert">{}</div>"#,
        variant,
        escape_html(message)
    )
}

fn oidc_footer(label: &str) -> String {
    format!(
        r#"{label} · <a href="/.well-known/openid-configuration">Configuration</a>"#,
        label = escape_html(label)
    )
}

/// Generate login page HTML.
#[allow(dead_code)]
pub fn login_page(params: &HashMap<String, String>, error: Option<&str>) -> String {
    let client_id = params.get("client_id").map(|s| s.as_str()).unwrap_or("");
    let redirect_uri = params.get("redirect_uri").map(|s| s.as_str()).unwrap_or("");
    let state = params.get("state").map(|s| s.as_str()).unwrap_or("");
    let nonce = params.get("nonce").map(|s| s.as_str()).unwrap_or("");
    let tenant = params.get("tenant").map(|s| s.as_str()).unwrap_or("");
    let scope = params.get("scope").map(|s| s.as_str()).unwrap_or("");
    let csrf_token = params.get("csrf_token").map(|s| s.as_str()).unwrap_or("");
    let code_challenge = params
        .get("code_challenge")
        .map(|s| s.as_str())
        .unwrap_or("");
    let code_challenge_method = params
        .get("code_challenge_method")
        .map(|s| s.as_str())
        .unwrap_or("");

    let error_html = error.map(|err| alert("danger", err)).unwrap_or_default();
    let body = format!(
        r#"{error_html}
<div class="alert alert-info" role="alert">
  Signing in to <strong>{client}</strong>
</div>
<form method="POST" action="/oauth2/login">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="nonce" value="{nonce}">
  <input type="hidden" name="tenant" value="{tenant}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
  <div class="mb-3">
    <label class="form-label" for="username">Email or username</label>
    <input class="form-control" type="text" id="username" name="username" required autofocus autocomplete="username" placeholder="{placeholder}">
  </div>
  <div class="mb-3">
    <label class="form-label" for="password">Password</label>
    <input class="form-control" type="password" id="password" name="password" required autocomplete="current-password" placeholder="********">
  </div>
  <button type="submit" class="btn btn-primary w-100">Sign in</button>
</form>"#,
        error_html = error_html,
        client = escape_html(client_id),
        client_id = escape_html(client_id),
        redirect_uri = escape_html(redirect_uri),
        state = escape_html(state),
        nonce = escape_html(nonce),
        tenant = escape_html(tenant),
        scope = escape_html(scope),
        csrf_token = escape_html(csrf_token),
        code_challenge = escape_html(code_challenge),
        code_challenge_method = escape_html(code_challenge_method),
        placeholder = escape_html(&user_placeholder())
    );

    render_page(
        "Sign in",
        &brand_label(),
        "Sign in to your workspace",
        &default_description(),
        &body,
        &oidc_footer("Protected by OAuth 2.0 + OIDC"),
        "",
    )
}

/// Generate error page HTML.
#[allow(dead_code)]
pub fn error_page(error: &str, error_description: &str) -> String {
    let body = format!(
        r#"<div class="alert alert-danger" role="alert">
  <div class="fw-semibold mb-1">Authorization error</div>
  <div>{}</div>
  <div class="small mt-2">Error code: <code>{}</code></div>
</div>
<a href="javascript:history.back()" class="btn btn-primary w-100">Go back</a>"#,
        escape_html(error_description),
        escape_html(error)
    );

    render_page(
        "Error",
        &brand_label(),
        "Sign in to your workspace",
        &default_description(),
        &body,
        &oidc_footer("Protected by OAuth 2.0 + OIDC"),
        "container-narrow",
    )
}

#[allow(dead_code)]
pub fn password_reset_page(token: &str, error: Option<&str>) -> String {
    let error_html = error.map(|err| alert("danger", err)).unwrap_or_default();
    let body = format!(
        r#"{error_html}
<form method="POST" action="/password/reset">
  <input type="hidden" name="token" value="{token}">
  <div class="mb-3">
    <label class="form-label" for="password">New password</label>
    <input class="form-control" type="password" id="password" name="password" required autocomplete="new-password" placeholder="Create a strong password">
  </div>
  <div class="mb-3">
    <label class="form-label" for="password_confirm">Confirm password</label>
    <input class="form-control" type="password" id="password_confirm" name="password_confirm" required autocomplete="new-password" placeholder="Repeat your password">
  </div>
  <button type="submit" class="btn btn-primary w-100">Update password</button>
</form>"#,
        error_html = error_html,
        token = escape_html(token)
    );

    render_page(
        "Reset password",
        &brand_label(),
        "Set a new password",
        "Choose a strong password you do not use elsewhere.",
        &body,
        &oidc_footer("Protected by OAuth 2.0 + OIDC"),
        "",
    )
}

#[allow(dead_code)]
pub fn password_reset_success_page() -> String {
    let body = r#"<div class="alert alert-success" role="alert">
  Your password has been updated successfully.
</div>"#;

    render_page(
        "Password updated",
        &brand_label(),
        "Password updated",
        "You can now close this window or return to your app.",
        body,
        &oidc_footer("Protected by OAuth 2.0 + OIDC"),
        "",
    )
}

/// Generate device verification form page HTML.
#[allow(dead_code)]
pub fn device_verify_page(
    user_code: Option<&str>,
    error: Option<&str>,
    success: Option<&str>,
) -> String {
    let error_html = error.map(|err| alert("danger", err)).unwrap_or_default();
    let success_html = success.map(|msg| alert("success", msg)).unwrap_or_default();
    let user_code_value = user_code.unwrap_or("");

    let body = format!(
        r#"{error_html}
{success_html}
<form method="POST" action="/device">
  <div class="mb-3">
    <label class="form-label" for="user_code">Device code</label>
    <input class="form-control text-center font-monospace text-uppercase" type="text" id="user_code" name="user_code" value="{user_code}" required autofocus placeholder="XXXX-XXXX" pattern="[A-Z0-9]{{4}}-[A-Z0-9]{{4}}" maxlength="9">
    <div class="form-hint">Format: XXXX-XXXX (8 characters)</div>
  </div>
  <div class="mb-3">
    <label class="form-label" for="username">Email or username</label>
    <input class="form-control" type="text" id="username" name="username" required autocomplete="username" placeholder="{placeholder}">
  </div>
  <div class="mb-3">
    <label class="form-label" for="password">Password</label>
    <input class="form-control" type="password" id="password" name="password" required autocomplete="current-password" placeholder="********">
  </div>
  <button type="submit" class="btn btn-primary w-100">Authorize device</button>
</form>"#,
        error_html = error_html,
        success_html = success_html,
        user_code = escape_html(user_code_value),
        placeholder = escape_html(&user_placeholder())
    );

    render_page(
        "Device authorization",
        "Device Authorization",
        "Connect your device",
        "Enter the code shown on your device and sign in to authorize access.",
        &body,
        &oidc_footer("Protected by OAuth 2.0 Device Flow"),
        "",
    )
}

/// Generate callback HTML.
/// This page will post a message to the opener window and close itself.
#[allow(dead_code)]
pub fn callback_page(success: bool, base_header: &str, detail: &str) -> Html<String> {
    let (title, heading, variant) = if success {
        ("Login successful", "Login successful", "success")
    } else {
        ("Login failed", "Login failed", "danger")
    };

    let detail = escape_html(detail);
    let body = format!(
        r#"<div class="alert alert-{variant}" role="alert">{detail}</div>
<button type="button" onclick="window.close();" class="btn btn-primary w-100">Close window</button>"#,
        variant = variant,
        detail = detail
    );

    Html(render_page(
        title,
        base_header,
        heading,
        &detail,
        &body,
        "Protected by OAuth 2.0 Device Flow",
        "",
    ))
}
