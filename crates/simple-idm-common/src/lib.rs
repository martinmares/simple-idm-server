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

    let badge = if success {
        "border-emerald-200 bg-emerald-50 text-emerald-700"
    } else {
        "border-red-200 bg-red-50 text-red-700"
    };

    Html(format!(
        r#"<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
  <title>{}</title>
  <script src=\"https://cdn.tailwindcss.com\"></script>
</head>
<body class=\"min-h-screen bg-slate-50 flex items-center justify-center p-4\">
  <div class=\"w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-lg\">
    <h1 class=\"text-xl font-bold text-slate-900\">{}</h1>
    <div class=\"mt-4 rounded-lg border px-4 py-3 text-sm {}\">{}</div>
    <p class=\"mt-3 text-xs text-slate-500\">You can close this window.</p>
  </div>
</body>
</html>"#,
        title, heading, badge, detail
    ))
}
