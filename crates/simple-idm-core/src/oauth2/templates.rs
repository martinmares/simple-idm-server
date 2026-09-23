/// HTML templates for OAuth2 Authorization Code Flow.
use axum::response::Html;
use simple_idm_common::tabler_standalone_page;
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
    format!("{} - {}", title, get_branding().page_title)
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
    tabler_standalone_page(
        &page_title(title),
        eyebrow,
        heading,
        description,
        body,
        footer,
        width_class,
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

pub fn mfa_challenge_page(error: Option<&str>) -> String {
    let error_html = error.map(|err| alert("danger", err)).unwrap_or_default();
    let body = format!(
        r#"{error_html}
<form method="POST" action="/oauth2/mfa">
  <div class="mb-3">
    <label class="form-label" for="code">Verification or recovery code</label>
    <input class="form-control font-monospace" type="text" inputmode="numeric" id="code" name="code" required autofocus autocomplete="one-time-code" placeholder="123456">
    <div class="form-hint">Enter the current code from your authenticator app. A one-time recovery code also works.</div>
  </div>
  <button type="submit" class="btn btn-primary w-100">Verify</button>
</form>"#,
        error_html = error_html,
    );

    render_page(
        "Verify your identity",
        &brand_label(),
        "Two-factor authentication",
        "Complete sign-in with your second factor.",
        &body,
        &oidc_footer("Protected by OAuth 2.0 + OIDC"),
        "",
    )
}

pub fn mfa_enrollment_page(base32_secret: &str, qr_svg: &str, error: Option<&str>) -> String {
    let error_html = error.map(|err| alert("danger", err)).unwrap_or_default();
    let body = format!(
        r#"{error_html}
<div class="text-center mb-3">{qr_svg}</div>
<div class="mb-3">
  <label class="form-label">Manual setup key</label>
  <div class="input-group"><input class="form-control font-monospace" value="{secret}" readonly></div>
</div>
<form method="POST" action="/oauth2/mfa">
  <div class="mb-3">
    <label class="form-label" for="code">Verification code</label>
    <input class="form-control font-monospace" type="text" inputmode="numeric" id="code" name="code" required autofocus autocomplete="one-time-code" placeholder="123456">
    <div class="form-hint">Scan the QR code with Microsoft Authenticator, Google Authenticator, or another TOTP application, then enter its current code.</div>
  </div>
  <button type="submit" class="btn btn-primary w-100">Enable two-factor authentication</button>
</form>"#,
        error_html = error_html,
        qr_svg = qr_svg,
        secret = escape_html(base32_secret),
    );

    render_page(
        "Set up two-factor authentication",
        &brand_label(),
        "Protect your account",
        "Your organization requires an authenticator app for locally managed accounts.",
        &body,
        &oidc_footer("TOTP authenticator enrollment"),
        "",
    )
}

pub fn recovery_codes_page(codes: &[String], continue_url: &str) -> String {
    let codes = codes
        .iter()
        .map(|code| escape_html(code))
        .collect::<Vec<_>>()
        .join("\n");
    let body = format!(
        r#"<div class="alert alert-warning" role="alert">
  <div class="fw-semibold mb-1">Save these recovery codes now</div>
  Each code works once. They will not be shown again. Store them outside this device.
</div>
<pre class="p-3 border rounded user-select-all"><code>{codes}</code></pre>
<a class="btn btn-primary w-100" href="{continue_url}">I saved the codes — continue</a>"#,
        codes = codes,
        continue_url = escape_html(continue_url),
    );

    render_page(
        "Recovery codes",
        &brand_label(),
        "Two-factor authentication enabled",
        "Keep a recovery code available in case you lose access to your authenticator.",
        &body,
        &oidc_footer("Recovery codes are single-use credentials"),
        "",
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
    let passkeys_enabled = params
        .get("passkeys_enabled")
        .is_some_and(|value| value == "true");
    let passkey_html = if passkeys_enabled {
        r#"<div class="text-center text-secondary my-3">or</div>
<button type="button" id="passkey-login" class="btn btn-outline-primary w-100">Continue with passkey</button>
<div id="passkey-message" class="form-hint mt-2" role="status" aria-live="polite"></div>"#
    } else {
        ""
    };
    let username_passkey_error = if passkeys_enabled {
        r#"<div id="username-passkey-error" class="invalid-feedback" role="alert"></div>"#
    } else {
        ""
    };
    let passkey_script = if passkeys_enabled {
        format!("<script>{}</script>", include_str!("passkey_ui.js"))
    } else {
        String::new()
    };
    let body = format!(
        r#"{error_html}
<div class="alert alert-info" role="alert">
  Signing in to <strong>{client}</strong>
</div>
<form method="POST" action="/oauth2/login" id="login-form">
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
    {username_passkey_error}
  </div>
  <div class="mb-3">
    <label class="form-label" for="password">Password</label>
    <input class="form-control" type="password" id="password" name="password" required autocomplete="current-password" placeholder="********">
  </div>
  <div class="mb-3">
    <label class="form-label" for="mfa_code">MFA or recovery code</label>
    <input class="form-control font-monospace" type="text" id="mfa_code" name="mfa_code" autocomplete="one-time-code" placeholder="Only required when MFA is enabled">
    <div class="form-hint">Local accounts with active or required MFA must provide a current authenticator code or a one-time recovery code.</div>
  </div>
  <button type="submit" class="btn btn-primary w-100">Sign in</button>
</form>
{passkey_html}
{passkey_script}"#,
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
        passkey_html = passkey_html,
        username_passkey_error = username_passkey_error,
        passkey_script = passkey_script,
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
