use axum::response::Html;

pub fn callback_page(success: bool, base_header: &str, detail: &str) -> Html<String> {
    let title = if success {
        format!("{} successful", base_header)
    } else {
        format!("{} failed", base_header)
    };

    let heading = if success {
        format!("{} successful", base_header)
    } else {
        format!("{} failed", base_header)
    };

    let detail = detail
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");

    let badge = if success { "success" } else { "danger" };

    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{}</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #f9fafb;
      --fg: #1f2937;
      --muted: #6b7280;
      --card: #ffffff;
      --border: #e5e7eb;
      --success-bg: #dff6e5;
      --success-fg: #1b7f37;
      --success-border: #a9e5b8;
      --danger-bg: #fae1e1;
      --danger-fg: #b42323;
      --danger-border: #f3b8b8;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #111827;
        --fg: #e5e7eb;
        --muted: #9ca3af;
        --card: #1f2937;
        --border: #374151;
        --success-bg: #12351f;
        --success-fg: #8bd79d;
        --success-border: #2f7d46;
        --danger-bg: #3a1616;
        --danger-fg: #e98e8e;
        --danger-border: #7f2d2d;
      }}
    }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
      background: var(--bg);
      color: var(--fg);
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    .card {{
      width: 100%;
      max-width: 28rem;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--card);
      padding: 1.5rem;
      box-shadow: 0 10px 28px rgba(0, 0, 0, .18);
    }}
    .badge {{
      margin-top: 1rem;
      border: 1px solid var(--{}-border);
      border-radius: 6px;
      background: var(--{}-bg);
      color: var(--{}-fg);
      padding: .75rem 1rem;
      font-size: .875rem;
    }}
    h1 {{ margin: 0; font-size: 1.25rem; }}
    p {{ color: var(--muted); font-size: .75rem; margin: .75rem 0 0; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{}</h1>
    <div class="badge">{}</div>
    <p>You can close this window.</p>
  </div>
</body>
</html>"#,
        title, badge, badge, badge, heading, detail
    ))
}
