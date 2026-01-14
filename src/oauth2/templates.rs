/// HTML templates for OAuth2 Authorization Code Flow
use std::collections::HashMap;

/// Generate login page HTML
pub fn login_page(params: &HashMap<String, String>, error: Option<&str>) -> String {
    let client_id = params.get("client_id").map(|s| s.as_str()).unwrap_or("");
    let redirect_uri = params.get("redirect_uri").map(|s| s.as_str()).unwrap_or("");
    let state = params.get("state").map(|s| s.as_str()).unwrap_or("");
    let scope = params.get("scope").map(|s| s.as_str()).unwrap_or("");
    let code_challenge = params.get("code_challenge").map(|s| s.as_str()).unwrap_or("");
    let code_challenge_method = params.get("code_challenge_method").map(|s| s.as_str()).unwrap_or("");

    let error_html = if let Some(err) = error {
        format!(
            r#"<div class="error-message">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
                </svg>
                {}
            </div>"#,
            err
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Přihlášení - Cloud App SSO</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}

        .login-container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 420px;
            width: 100%;
            padding: 48px 40px;
            animation: slideUp 0.4s ease-out;
        }}

        @keyframes slideUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        .logo {{
            text-align: center;
            margin-bottom: 32px;
        }}

        .logo h1 {{
            color: #667eea;
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
        }}

        .logo p {{
            color: #6b7280;
            font-size: 14px;
        }}

        .form-group {{
            margin-bottom: 24px;
        }}

        label {{
            display: block;
            color: #374151;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
        }}

        input[type="text"],
        input[type="password"] {{
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.2s;
            outline: none;
        }}

        input[type="text"]:focus,
        input[type="password"]:focus {{
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}

        .submit-btn {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            margin-top: 8px;
        }}

        .submit-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }}

        .submit-btn:active {{
            transform: translateY(0);
        }}

        .error-message {{
            background: #fee2e2;
            color: #991b1b;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 24px;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .client-info {{
            background: #f3f4f6;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 24px;
            font-size: 13px;
            color: #6b7280;
        }}

        .client-info strong {{
            color: #374151;
        }}

        .footer {{
            margin-top: 32px;
            text-align: center;
            font-size: 12px;
            color: #9ca3af;
        }}

        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}

        .footer a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🔐 Cloud App SSO</h1>
            <p>Bezpečné přihlášení</p>
        </div>

        {}

        <div class="client-info">
            <strong>Přihlášení do aplikace:</strong> {}
        </div>

        <form method="POST" action="/oauth2/login">
            <input type="hidden" name="client_id" value="{}">
            <input type="hidden" name="redirect_uri" value="{}">
            <input type="hidden" name="state" value="{}">
            <input type="hidden" name="scope" value="{}">
            <input type="hidden" name="code_challenge" value="{}">
            <input type="hidden" name="code_challenge_method" value="{}">

            <div class="form-group">
                <label for="username">Uživatelské jméno</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    required
                    autofocus
                    autocomplete="username"
                    placeholder="Zadejte uživatelské jméno"
                >
            </div>

            <div class="form-group">
                <label for="password">Heslo</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    required
                    autocomplete="current-password"
                    placeholder="Zadejte heslo"
                >
            </div>

            <button type="submit" class="submit-btn">
                Přihlásit se
            </button>
        </form>

        <div class="footer">
            <p>Chráněno pomocí OAuth 2.0 + OIDC</p>
            <p><a href="/.well-known/openid-configuration">Konfigurace</a></p>
        </div>
    </div>
</body>
</html>"#,
        error_html,
        client_id,
        client_id,
        redirect_uri,
        state,
        scope,
        code_challenge,
        code_challenge_method
    )
}

/// Generate error page HTML
pub fn error_page(error: &str, error_description: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chyba - Cloud App SSO</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}

        .error-container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            padding: 48px 40px;
            text-align: center;
        }}

        .error-icon {{
            font-size: 64px;
            margin-bottom: 24px;
        }}

        h1 {{
            color: #991b1b;
            font-size: 24px;
            margin-bottom: 16px;
        }}

        p {{
            color: #6b7280;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 32px;
        }}

        .error-code {{
            background: #fee2e2;
            color: #991b1b;
            padding: 12px 16px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            margin-top: 24px;
        }}

        .back-btn {{
            display: inline-block;
            padding: 12px 32px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.2s;
        }}

        .back-btn:hover {{
            background: #5568d3;
            transform: translateY(-2px);
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">⚠️</div>
        <h1>Chyba při autorizaci</h1>
        <p>{}</p>
        <div class="error-code">
            <strong>Kód chyby:</strong> {}
        </div>
        <p style="margin-top: 32px;">
            <a href="javascript:history.back()" class="back-btn">Zpět</a>
        </p>
    </div>
</body>
</html>"#,
        error_description, error
    )
}
