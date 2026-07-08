use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use base64::Engine;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/"]
struct UiAssets;

pub fn embedded_asset_response(path: &str) -> Response {
    let path = path.trim_start_matches('/');
    let Some(file) = UiAssets::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset_content_type(path)),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );

    (headers, file.data.into_owned()).into_response()
}

pub fn tabler_standalone_page(
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
  <title>{title}</title>
  <style>{tabler_css}</style>
  <style>{tabler_icons_css}</style>
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
  <div class="container-tight py-4 {width_class}">
    <div class="card card-md">
      <div class="card-body">
        <div class="mb-4">
          <div class="text-secondary text-uppercase fw-semibold small mb-2">{eyebrow}</div>
          <h1 class="h2 mb-2">{heading}</h1>
          <p class="text-secondary mb-0">{description}</p>
        </div>
        {body}
        <div class="mt-4 text-center text-secondary small">
          {footer}
        </div>
      </div>
    </div>
  </div>
</body>
</html>"#,
        title = escape_html(title),
        tabler_css = embedded_tabler_css(),
        tabler_icons_css = embedded_tabler_icons_css(),
        width_class = width_class,
        eyebrow = escape_html(eyebrow),
        heading = escape_html(heading),
        description = escape_html(description),
        body = body,
        footer = footer,
    )
}

pub fn callback_page(success: bool, base_header: &str, detail: &str) -> Html<String> {
    let (title, heading, variant) = if success {
        (
            format!("{} successful", base_header),
            format!("{} successful", base_header),
            "success",
        )
    } else {
        (
            format!("{} failed", base_header),
            format!("{} failed", base_header),
            "danger",
        )
    };

    let detail = escape_html(detail);
    let body = format!(
        r#"<div class="alert alert-{variant}" role="alert">{detail}</div>
<button type="button" onclick="window.close();" class="btn btn-primary w-100">Close window</button>"#,
        variant = variant,
        detail = detail
    );

    Html(tabler_standalone_page(
        &title,
        base_header,
        &heading,
        &detail,
        &body,
        "You can close this window.",
        "",
    ))
}

pub fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn embedded_text(path: &str) -> String {
    UiAssets::get(path)
        .map(|file| String::from_utf8_lossy(file.data.as_ref()).into_owned())
        .unwrap_or_default()
}

fn embedded_tabler_css() -> String {
    embedded_text("css/tabler.min.css").replace("/*# sourceMappingURL=tabler.min.css.map */", "")
}

fn embedded_tabler_icons_css() -> String {
    let css = embedded_text("css/tabler-icons.min.css")
        .replace("/*# sourceMappingURL=tabler-icons.min.css.map */", "");
    let Some(font) = UiAssets::get("fonts/tabler-icons.woff2") else {
        return css;
    };

    let font_b64 = base64::engine::general_purpose::STANDARD.encode(font.data.as_ref());
    let font_face = format!(
        r#"@font-face{{font-family:"tabler-icons";font-style:normal;font-weight:400;src:url("data:font/woff2;base64,{font_b64}") format("woff2")}}"#
    );
    replace_tabler_icons_font_face(&css, &font_face)
}

fn replace_tabler_icons_font_face(css: &str, replacement: &str) -> String {
    let Some(start) = css.find(r#"@font-face{font-family:"tabler-icons""#) else {
        return css.to_string();
    };
    let Some(end_rel) = css[start..].find("}.ti{") else {
        return css.to_string();
    };
    let end = start + end_rel + 1;

    let mut out = String::with_capacity(css.len() + replacement.len());
    out.push_str(&css[..start]);
    out.push_str(replacement);
    out.push_str(&css[end..]);
    out
}

fn asset_content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or_default() {
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        _ => "application/octet-stream",
    }
}
