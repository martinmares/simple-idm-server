/// HTML templates for OAuth2 Authorization Code Flow
use axum::response::Html;
use std::collections::HashMap;

/// Generate login page HTML
#[allow(dead_code)]
pub fn login_page(params: &HashMap<String, String>, error: Option<&str>) -> String {
    let client_id = params.get("client_id").map(|s| s.as_str()).unwrap_or("");
    let redirect_uri = params.get("redirect_uri").map(|s| s.as_str()).unwrap_or("");
    let state = params.get("state").map(|s| s.as_str()).unwrap_or("");
    let nonce = params.get("nonce").map(|s| s.as_str()).unwrap_or("");
    let scope = params.get("scope").map(|s| s.as_str()).unwrap_or("");
    let code_challenge = params
        .get("code_challenge")
        .map(|s| s.as_str())
        .unwrap_or("");
    let code_challenge_method = params
        .get("code_challenge_method")
        .map(|s| s.as_str())
        .unwrap_or("");

    let error_html = if let Some(err) = error {
        format!(
            r#"<div class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-200">
                <div class="flex items-center gap-2">
                    <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
                    </svg>
                    <span>{}</span>
                </div>
            </div>"#,
            err
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - Cloud App SSO</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'media',
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Avenir Next', 'Trebuchet MS', 'Lucida Grande', 'sans-serif']
                    }}
                }}
            }}
        }}
    </script>
    <style>
        :root {{
            --bg-start: #f1f5f9;
            --bg-mid: #e2e8f0;
            --bg-end: #f1f5f9;
            --streak-1: rgba(59, 130, 246, 0.25);
            --streak-2: rgba(96, 165, 250, 0.35);
        }}

        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg-start: #05080f;
                --bg-mid: #080f1a;
                --bg-end: #05080f;
                --streak-1: rgba(84, 141, 214, 0.6);
                --streak-2: rgba(120, 170, 235, 0.75);
            }}
        }}

        .bg-shell {{
            background: linear-gradient(
                135deg,
                var(--bg-start) 0%,
                var(--bg-mid) 50%,
                var(--bg-end) 100%
            );
        }}

        .bg-streak {{
            position: absolute;
            left: -30%;
            top: -30%;
            width: 200%;
            height: 2px;
            background: linear-gradient(
                90deg,
                transparent,
                var(--streak-1),
                var(--streak-2),
                transparent
            );
            opacity: 0;
            transform: rotate(35deg);
            animation: streakMove 12s ease-in-out infinite;
        }}

        .bg-streak.streak-2 {{
            animation-duration: 15s;
            animation-delay: 3s;
            height: 3px;
            opacity: 0;
        }}

        .bg-streak.streak-3 {{
            animation-duration: 18s;
            animation-delay: 6s;
            height: 2px;
            opacity: 0;
        }}

        .bg-streak.streak-4 {{
            animation-duration: 20s;
            animation-delay: 9s;
            height: 1px;
            opacity: 0;
        }}

        .bg-streak.streak-5 {{
            animation-duration: 22s;
            animation-delay: 12s;
            height: 2px;
            opacity: 0;
        }}

        .bg-streak.streak-6 {{
            animation-duration: 26s;
            animation-delay: 15s;
            height: 3px;
            opacity: 0;
        }}

        @keyframes streakMove {{
            0% {{
                transform: translate(-40%, -40%) rotate(35deg);
                opacity: 0;
            }}
            8% {{
                opacity: 0.9;
            }}
            16% {{
                opacity: 0;
            }}
            100% {{
                transform: translate(40%, 40%) rotate(35deg);
                opacity: 0;
            }}
        }}
    </style>
</head>
<body class="relative min-h-screen overflow-hidden px-4 py-10 font-sans text-slate-900 dark:text-slate-100">
    <div class="absolute inset-0 -z-10 bg-shell"></div>
    <div class="bg-streak streak-1 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-2 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-3 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-4 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-5 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-6 z-0 pointer-events-none"></div>
    <div class="relative z-10 mx-auto flex w-full max-w-md items-center justify-center">
        <div class="rounded-2xl border border-slate-200 bg-white p-8 shadow-md dark:border-slate-800 dark:bg-slate-900 dark:shadow-xl">
            <div class="mb-6">
                <p class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">Cloud App</p>
                <h1 class="mt-2 text-2xl font-semibold text-slate-900 dark:text-white">Sign in to your workspace</h1>
                <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">Secure sign-in for internal dashboards and admin tools.</p>
            </div>

            <div class="space-y-4">
                {}
            </div>

            <div class="mt-5 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-xs text-slate-500 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-400">
                Signing in to <span class="font-semibold text-slate-900 dark:text-white">{}</span>
            </div>

            <form method="POST" action="/oauth2/login" class="mt-6 space-y-4">
                <input type="hidden" name="client_id" value="{}">
                <input type="hidden" name="redirect_uri" value="{}">
                <input type="hidden" name="state" value="{}">
                <input type="hidden" name="nonce" value="{}">
                <input type="hidden" name="scope" value="{}">
                <input type="hidden" name="code_challenge" value="{}">
                <input type="hidden" name="code_challenge_method" value="{}">

                <div>
                    <label for="username" class="text-sm font-medium text-slate-700 dark:text-slate-200">Email or username</label>
                    <input
                        type="text"
                        id="username"
                        name="username"
                        required
                        autofocus
                        autocomplete="username"
                        placeholder="you@company.com"
                        class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm transition focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-slate-400 dark:focus:ring-slate-500/30"
                    >
                </div>

                <div>
                    <label for="password" class="text-sm font-medium text-slate-700 dark:text-slate-200">Password</label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        required
                        autocomplete="current-password"
                        placeholder="••••••••"
                        class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm transition focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-slate-400 dark:focus:ring-slate-500/30"
                    >
                </div>

                <button type="submit" class="mt-2 w-full rounded-xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-200">
                    Sign in
                </button>
            </form>

            <div class="mt-6 text-center text-xs text-slate-500 dark:text-slate-400">
                Protected by OAuth 2.0 + OIDC •
                <a class="font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white" href="/.well-known/openid-configuration">Configuration</a>
            </div>
        </div>
    </div>
</body>
</html>"#,
        error_html,
        client_id,
        client_id,
        redirect_uri,
        state,
        nonce,
        scope,
        code_challenge,
        code_challenge_method
    )
}

/// Generate error page HTML
#[allow(dead_code)]
pub fn error_page(error: &str, error_description: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Cloud App SSO</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'media',
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Avenir Next', 'Trebuchet MS', 'Lucida Grande', 'sans-serif']
                    }}
                }}
            }}
        }}
    </script>
    <style>
        :root {{
            --bg-start: #f1f5f9;
            --bg-mid: #e2e8f0;
            --bg-end: #f1f5f9;
            --streak-1: rgba(59, 130, 246, 0.25);
            --streak-2: rgba(96, 165, 250, 0.35);
        }}

        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg-start: #05080f;
                --bg-mid: #080f1a;
                --bg-end: #05080f;
                --streak-1: rgba(84, 141, 214, 0.6);
                --streak-2: rgba(120, 170, 235, 0.75);
            }}
        }}

        .bg-shell {{
            background: linear-gradient(
                135deg,
                var(--bg-start) 0%,
                var(--bg-mid) 50%,
                var(--bg-end) 100%
            );
        }}

        .bg-streak {{
            position: absolute;
            left: -30%;
            top: -30%;
            width: 200%;
            height: 2px;
            background: linear-gradient(
                90deg,
                transparent,
                var(--streak-1),
                var(--streak-2),
                transparent
            );
            opacity: 0;
            transform: rotate(35deg);
            animation: streakMove 12s ease-in-out infinite;
        }}

        .bg-streak.streak-2 {{
            animation-duration: 15s;
            animation-delay: 3s;
            height: 3px;
            opacity: 0;
        }}

        .bg-streak.streak-3 {{
            animation-duration: 18s;
            animation-delay: 6s;
            height: 2px;
            opacity: 0;
        }}

        .bg-streak.streak-4 {{
            animation-duration: 20s;
            animation-delay: 9s;
            height: 1px;
            opacity: 0;
        }}

        .bg-streak.streak-5 {{
            animation-duration: 22s;
            animation-delay: 12s;
            height: 2px;
            opacity: 0;
        }}

        .bg-streak.streak-6 {{
            animation-duration: 26s;
            animation-delay: 15s;
            height: 3px;
            opacity: 0;
        }}

        @keyframes streakMove {{
            0% {{
                transform: translate(-40%, -40%) rotate(35deg);
                opacity: 0;
            }}
            8% {{
                opacity: 0.9;
            }}
            16% {{
                opacity: 0;
            }}
            100% {{
                transform: translate(40%, 40%) rotate(35deg);
                opacity: 0;
            }}
        }}
    </style>
</head>
<body class="relative min-h-screen overflow-hidden px-4 py-10 font-sans text-slate-900 dark:text-slate-100">
    <div class="absolute inset-0 -z-10 bg-shell"></div>
    <div class="bg-streak streak-1 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-2 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-3 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-4 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-5 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-6 z-0 pointer-events-none"></div>
    <div class="relative z-10 mx-auto flex w-full max-w-lg items-center justify-center">
        <div class="rounded-2xl border border-slate-200 bg-white p-10 shadow-md dark:border-slate-800 dark:bg-slate-900 dark:shadow-xl">
            <div class="mb-6">
                <p class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">Cloud App</p>
                <h1 class="mt-2 text-2xl font-semibold text-slate-900 dark:text-white">Sign in to your workspace</h1>
                <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">Secure sign-in for internal dashboards and admin tools.</p>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-300">
                <div class="flex items-start gap-3">
                    <div class="mt-0.5 flex h-9 w-9 items-center justify-center rounded-full bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-200">
                        <svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4m0 4h.01M10.29 3.86l-7.1 12.27A2 2 0 004.9 19h14.2a2 2 0 001.71-2.87l-7.1-12.27a2 2 0 00-3.42 0z" />
                        </svg>
                    </div>
                    <div>
                        <p class="font-medium text-slate-900 dark:text-white">Authorization error</p>
                        <p class="mt-1 text-sm text-slate-600 dark:text-slate-400">{}</p>
                        <p class="mt-3 text-xs font-medium text-red-700 dark:text-red-300">Error code: {}</p>
                    </div>
                </div>
            </div>

            <div class="mt-6">
                <a href="javascript:history.back()" class="inline-flex w-full items-center justify-center rounded-xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-200">
                    Go back
                </a>
            </div>

            <div class="mt-6 text-center text-xs text-slate-500 dark:text-slate-400">
                Protected by OAuth 2.0 + OIDC •
                <a class="font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white" href="/.well-known/openid-configuration">Configuration</a>
            </div>
        </div>
    </div>
</body>
</html>"#,
        error_description, error
    )
}

#[allow(dead_code)]
pub fn password_reset_page(token: &str, error: Option<&str>) -> String {
    let error_html = if let Some(err) = error {
        format!(
            r#"<div class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-200">
                <div class="flex items-center gap-2">
                    <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
                    </svg>
                    <span>{}</span>
                </div>
            </div>"#,
            err
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - Cloud App SSO</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'media',
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Avenir Next', 'Trebuchet MS', 'Lucida Grande', 'sans-serif']
                    }}
                }}
            }}
        }}
    </script>
    <style>
        :root {{
            --bg-start: #f1f5f9;
            --bg-mid: #e2e8f0;
            --bg-end: #f1f5f9;
            --streak-1: rgba(59, 130, 246, 0.25);
            --streak-2: rgba(96, 165, 250, 0.35);
        }}

        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg-start: #05080f;
                --bg-mid: #080f1a;
                --bg-end: #05080f;
                --streak-1: rgba(84, 141, 214, 0.6);
                --streak-2: rgba(120, 170, 235, 0.75);
            }}
        }}

        .bg-shell {{
            background: linear-gradient(
                135deg,
                var(--bg-start) 0%,
                var(--bg-mid) 50%,
                var(--bg-end) 100%
            );
        }}

        .bg-streak {{
            position: absolute;
            left: -30%;
            top: -30%;
            width: 200%;
            height: 2px;
            background: linear-gradient(
                90deg,
                transparent,
                var(--streak-1),
                var(--streak-2),
                transparent
            );
            opacity: 0;
            transform: rotate(35deg);
            animation: streakMove 12s ease-in-out infinite;
        }}

        .bg-streak.streak-2 {{
            animation-duration: 15s;
            animation-delay: 3s;
            height: 3px;
            opacity: 0;
        }}

        .bg-streak.streak-3 {{
            animation-duration: 18s;
            animation-delay: 6s;
            height: 2px;
            opacity: 0;
        }}

        .bg-streak.streak-4 {{
            animation-duration: 20s;
            animation-delay: 9s;
            height: 1px;
            opacity: 0;
        }}

        .bg-streak.streak-5 {{
            animation-duration: 22s;
            animation-delay: 12s;
            height: 2px;
            opacity: 0;
        }}

        .bg-streak.streak-6 {{
            animation-duration: 26s;
            animation-delay: 15s;
            height: 3px;
            opacity: 0;
        }}

        @keyframes streakMove {{
            0% {{
                transform: translate(-40%, -40%) rotate(35deg);
                opacity: 0;
            }}
            8% {{
                opacity: 0.9;
            }}
            16% {{
                opacity: 0;
            }}
            100% {{
                transform: translate(40%, 40%) rotate(35deg);
                opacity: 0;
            }}
        }}
    </style>
</head>
<body class="relative min-h-screen overflow-hidden px-4 py-10 font-sans text-slate-900 dark:text-slate-100">
    <div class="absolute inset-0 -z-10 bg-shell"></div>
    <div class="bg-streak streak-1 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-2 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-3 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-4 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-5 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-6 z-0 pointer-events-none"></div>
    <div class="relative z-10 mx-auto flex w-full max-w-md items-center justify-center">
        <div class="rounded-2xl border border-slate-200 bg-white p-8 shadow-md dark:border-slate-800 dark:bg-slate-900 dark:shadow-xl">
            <div class="mb-6">
                <p class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">Cloud App</p>
                <h1 class="mt-2 text-2xl font-semibold text-slate-900 dark:text-white">Set a new password</h1>
                <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">Choose a strong password you don't use elsewhere.</p>
            </div>

            <div class="space-y-4">
                {}
            </div>

            <form method="POST" action="/password/reset" class="mt-6 space-y-4">
                <input type="hidden" name="token" value="{}">
                <div>
                    <label for="password" class="text-sm font-medium text-slate-700 dark:text-slate-200">New password</label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        required
                        autocomplete="new-password"
                        placeholder="Create a strong password"
                        class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm transition focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-slate-400 dark:focus:ring-slate-500/30"
                    >
                </div>

                <div>
                    <label for="password_confirm" class="text-sm font-medium text-slate-700 dark:text-slate-200">Confirm password</label>
                    <input
                        type="password"
                        id="password_confirm"
                        name="password_confirm"
                        required
                        autocomplete="new-password"
                        placeholder="Repeat your password"
                        class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm transition focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-slate-400 dark:focus:ring-slate-500/30"
                    >
                </div>

                <button type="submit" class="mt-2 w-full rounded-xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-200">
                    Update password
                </button>
            </form>

            <div class="mt-6 text-center text-xs text-slate-500 dark:text-slate-400">
                Protected by OAuth 2.0 + OIDC •
                <a class="font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white" href="/.well-known/openid-configuration">Configuration</a>
            </div>
        </div>
    </div>
</body>
</html>"#,
        error_html, token
    )
}

#[allow(dead_code)]
pub fn password_reset_success_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Updated - Cloud App SSO</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'media',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Avenir Next', 'Trebuchet MS', 'Lucida Grande', 'sans-serif']
                    }
                }
            }
        }
    </script>
    <style>
        :root {
            --bg-start: #f1f5f9;
            --bg-mid: #e2e8f0;
            --bg-end: #f1f5f9;
            --streak-1: rgba(59, 130, 246, 0.25);
            --streak-2: rgba(96, 165, 250, 0.35);
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-start: #05080f;
                --bg-mid: #080f1a;
                --bg-end: #05080f;
                --streak-1: rgba(84, 141, 214, 0.6);
                --streak-2: rgba(120, 170, 235, 0.75);
            }
        }

        .bg-shell {
            background: linear-gradient(
                135deg,
                var(--bg-start) 0%,
                var(--bg-mid) 50%,
                var(--bg-end) 100%
            );
        }

        .bg-streak {
            position: absolute;
            left: -30%;
            top: -30%;
            width: 200%;
            height: 2px;
            background: linear-gradient(
                90deg,
                transparent,
                var(--streak-1),
                var(--streak-2),
                transparent
            );
            opacity: 0;
            transform: rotate(35deg);
            animation: streakMove 12s ease-in-out infinite;
        }

        .bg-streak.streak-2 {
            animation-duration: 15s;
            animation-delay: 3s;
            height: 3px;
            opacity: 0;
        }

        .bg-streak.streak-3 {
            animation-duration: 18s;
            animation-delay: 6s;
            height: 2px;
            opacity: 0;
        }

        .bg-streak.streak-4 {
            animation-duration: 20s;
            animation-delay: 9s;
            height: 1px;
            opacity: 0;
        }

        .bg-streak.streak-5 {
            animation-duration: 22s;
            animation-delay: 12s;
            height: 2px;
            opacity: 0;
        }

        .bg-streak.streak-6 {
            animation-duration: 26s;
            animation-delay: 15s;
            height: 3px;
            opacity: 0;
        }

        @keyframes streakMove {
            0% {
                transform: translate(-40%, -40%) rotate(35deg);
                opacity: 0;
            }
            8% {
                opacity: 0.9;
            }
            16% {
                opacity: 0;
            }
            100% {
                transform: translate(40%, 40%) rotate(35deg);
                opacity: 0;
            }
        }
    </style>
</head>
<body class="relative min-h-screen overflow-hidden px-4 py-10 font-sans text-slate-900 dark:text-slate-100">
    <div class="absolute inset-0 -z-10 bg-shell"></div>
    <div class="bg-streak streak-1 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-2 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-3 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-4 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-5 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-6 z-0 pointer-events-none"></div>
    <div class="relative z-10 mx-auto flex w-full max-w-md items-center justify-center">
        <div class="rounded-2xl border border-slate-200 bg-white p-8 shadow-md dark:border-slate-800 dark:bg-slate-900 dark:shadow-xl">
            <div class="mb-6">
                <p class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">Cloud App</p>
                <h1 class="mt-2 text-2xl font-semibold text-slate-900 dark:text-white">Password updated</h1>
                <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">You can now close this window or return to your app.</p>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-300">
                Your password has been updated successfully.
            </div>

            <div class="mt-6 text-center text-xs text-slate-500 dark:text-slate-400">
                Protected by OAuth 2.0 + OIDC •
                <a class="font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white" href="/.well-known/openid-configuration">Configuration</a>
            </div>
        </div>
    </div>
</body>
</html>"#
        .to_string()
}

/// Generate device verification form page HTML
#[allow(dead_code)]
pub fn device_verify_page(
    user_code: Option<&str>,
    error: Option<&str>,
    success: Option<&str>,
) -> String {
    let error_html = if let Some(err) = error {
        format!(
            r#"<div class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-200">
                <div class="flex items-center gap-2">
                    <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
                    </svg>
                    <span>{}</span>
                </div>
            </div>"#,
            err
        )
    } else {
        String::new()
    };

    let success_html = if let Some(msg) = success {
        format!(
            r#"<div class="rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700 dark:border-green-500/30 dark:bg-green-500/10 dark:text-green-200">
                <div class="flex items-center gap-2">
                    <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                    </svg>
                    <span>{}</span>
                </div>
            </div>"#,
            msg
        )
    } else {
        String::new()
    };

    let user_code_value = user_code.unwrap_or("");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Authorization - Cloud App SSO</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'media',
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Avenir Next', 'Trebuchet MS', 'Lucida Grande', 'sans-serif']
                    }}
                }}
            }}
        }}
    </script>
    <style>
        :root {{
            --bg-start: #f1f5f9;
            --bg-mid: #e2e8f0;
            --bg-end: #f1f5f9;
            --streak-1: rgba(59, 130, 246, 0.25);
            --streak-2: rgba(96, 165, 250, 0.35);
        }}

        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg-start: #05080f;
                --bg-mid: #080f1a;
                --bg-end: #05080f;
                --streak-1: rgba(84, 141, 214, 0.6);
                --streak-2: rgba(120, 170, 235, 0.75);
            }}
        }}

        .bg-shell {{
            background: linear-gradient(
                135deg,
                var(--bg-start) 0%,
                var(--bg-mid) 50%,
                var(--bg-end) 100%
            );
        }}

        .bg-streak {{
            position: absolute;
            left: -30%;
            top: -30%;
            width: 200%;
            height: 2px;
            background: linear-gradient(
                90deg,
                transparent,
                var(--streak-1),
                var(--streak-2),
                transparent
            );
            opacity: 0;
            transform: rotate(35deg);
            animation: streakMove 12s ease-in-out infinite;
        }}

        .bg-streak.streak-2 {{
            animation-duration: 15s;
            animation-delay: 3s;
            height: 3px;
            opacity: 0;
        }}

        .bg-streak.streak-3 {{
            animation-duration: 18s;
            animation-delay: 6s;
            height: 2px;
            opacity: 0;
        }}

        .bg-streak.streak-4 {{
            animation-duration: 20s;
            animation-delay: 9s;
            height: 1px;
            opacity: 0;
        }}

        .bg-streak.streak-5 {{
            animation-duration: 22s;
            animation-delay: 12s;
            height: 2px;
            opacity: 0;
        }}

        .bg-streak.streak-6 {{
            animation-duration: 26s;
            animation-delay: 15s;
            height: 3px;
            opacity: 0;
        }}

        @keyframes streakMove {{
            0% {{
                transform: translate(-40%, -40%) rotate(35deg);
                opacity: 0;
            }}
            8% {{
                opacity: 0.9;
            }}
            16% {{
                opacity: 0;
            }}
            100% {{
                transform: translate(40%, 40%) rotate(35deg);
                opacity: 0;
            }}
        }}
    </style>
</head>
<body class="relative min-h-screen overflow-hidden px-4 py-10 font-sans text-slate-900 dark:text-slate-100">
    <div class="absolute inset-0 -z-10 bg-shell"></div>
    <div class="bg-streak streak-1 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-2 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-3 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-4 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-5 z-0 pointer-events-none"></div>
    <div class="bg-streak streak-6 z-0 pointer-events-none"></div>
    <div class="relative z-10 mx-auto flex w-full max-w-md items-center justify-center">
        <div class="rounded-2xl border border-slate-200 bg-white p-8 shadow-md dark:border-slate-800 dark:bg-slate-900 dark:shadow-xl">
            <div class="mb-6">
                <p class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">Device Authorization</p>
                <h1 class="mt-2 text-2xl font-semibold text-slate-900 dark:text-white">Connect your device</h1>
                <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">Enter the code shown on your device and sign in to authorize access.</p>
            </div>

            <div class="space-y-4">
                {}
                {}
            </div>

            <form method="POST" action="/device" class="mt-6 space-y-4">
                <div>
                    <label for="user_code" class="text-sm font-medium text-slate-700 dark:text-slate-200">Device code</label>
                    <input
                        type="text"
                        id="user_code"
                        name="user_code"
                        value="{}"
                        required
                        autofocus
                        placeholder="XXXX-XXXX"
                        pattern="[A-Z0-9]{{4}}-[A-Z0-9]{{4}}"
                        maxlength="9"
                        class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 font-mono text-center tracking-wider uppercase shadow-sm transition focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-slate-400 dark:focus:ring-slate-500/30"
                    >
                    <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">Format: XXXX-XXXX (8 characters)</p>
                </div>

                <div>
                    <label for="username" class="text-sm font-medium text-slate-700 dark:text-slate-200">Email or username</label>
                    <input
                        type="text"
                        id="username"
                        name="username"
                        required
                        autocomplete="username"
                        placeholder="you@company.com"
                        class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm transition focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-slate-400 dark:focus:ring-slate-500/30"
                    >
                </div>

                <div>
                    <label for="password" class="text-sm font-medium text-slate-700 dark:text-slate-200">Password</label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        required
                        autocomplete="current-password"
                        placeholder="••••••••"
                        class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm transition focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-slate-400 dark:focus:ring-slate-500/30"
                    >
                </div>

                <button type="submit" class="mt-2 w-full rounded-xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-200">
                    Authorize device
                </button>
            </form>

            <div class="mt-6 text-center text-xs text-slate-500 dark:text-slate-400">
                Protected by OAuth 2.0 Device Flow •
                <a class="font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white" href="/.well-known/openid-configuration">Configuration</a>
            </div>
        </div>
    </div>
</body>
</html>"#,
        error_html, success_html, user_code_value
    )
}

/// Generate callback HTML
/// This page will post a message to the opener window and close itself
#[allow(dead_code)]
pub fn callback_page(success: bool, base_header: &str, detail: &str) -> Html<String> {
    let (title, heading, box_classes, icon_svg) = if success {
        (
            "Login successful",
            "Login successful!",
            "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-200",
            r#"<svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.707a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 10-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
               </svg>"#,
        )
    } else {
        (
            "Login failed",
            "Login failed!",
            "border-red-200 bg-red-50 text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-200",
            r#"<svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
               </svg>"#,
        )
    };

    // (Volitelné) velmi jednoduché HTML escaping, ať ti tam jednou nepřileze '<'
    let detail = detail
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");

    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {{
      darkMode: 'media',
      theme: {{
        extend: {{
          fontFamily: {{
            sans: ['Avenir Next', 'Trebuchet MS', 'Lucida Grande', 'sans-serif']
          }}
        }}
      }}
    }}
  </script>
  <style>
    :root {{
      --bg-start: #f1f5f9;
      --bg-mid: #e2e8f0;
      --bg-end: #f1f5f9;
      --streak-1: rgba(59, 130, 246, 0.25);
      --streak-2: rgba(96, 165, 250, 0.35);
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg-start: #05080f;
        --bg-mid: #080f1a;
        --bg-end: #05080f;
        --streak-1: rgba(84, 141, 214, 0.6);
        --streak-2: rgba(120, 170, 235, 0.75);
      }}
    }}
    .bg-shell {{
      background: linear-gradient(135deg, var(--bg-start) 0%, var(--bg-mid) 50%, var(--bg-end) 100%);
    }}
    .bg-streak {{
      position: absolute;
      left: -30%;
      top: -30%;
      width: 200%;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--streak-1), var(--streak-2), transparent);
      opacity: 0;
      transform: rotate(35deg);
      animation: streakMove 12s ease-in-out infinite;
    }}
    .bg-streak.streak-2 {{ animation-duration: 15s; animation-delay: 3s; height: 3px; }}
    .bg-streak.streak-3 {{ animation-duration: 18s; animation-delay: 6s; height: 2px; }}
    .bg-streak.streak-4 {{ animation-duration: 20s; animation-delay: 9s; height: 1px; }}
    .bg-streak.streak-5 {{ animation-duration: 22s; animation-delay: 12s; height: 2px; }}
    .bg-streak.streak-6 {{ animation-duration: 26s; animation-delay: 15s; height: 3px; }}
    @keyframes streakMove {{
      0% {{ transform: translate(-40%, -40%) rotate(35deg); opacity: 0; }}
      8% {{ opacity: 0.9; }}
      16% {{ opacity: 0; }}
      100% {{ transform: translate(40%, 40%) rotate(35deg); opacity: 0; }}
    }}
  </style>
</head>

<body class="relative min-h-screen overflow-hidden px-4 py-10 font-sans text-slate-900 dark:text-slate-100">
  <div class="absolute inset-0 -z-10 bg-shell"></div>
  <div class="bg-streak streak-1 z-0 pointer-events-none"></div>
  <div class="bg-streak streak-2 z-0 pointer-events-none"></div>
  <div class="bg-streak streak-3 z-0 pointer-events-none"></div>
  <div class="bg-streak streak-4 z-0 pointer-events-none"></div>
  <div class="bg-streak streak-5 z-0 pointer-events-none"></div>
  <div class="bg-streak streak-6 z-0 pointer-events-none"></div>

  <div class="relative z-10 mx-auto flex w-full max-w-md items-center justify-center">
    <div class="rounded-2xl border border-slate-200 bg-white p-8 shadow-md dark:border-slate-800 dark:bg-slate-900 dark:shadow-xl">
      <div class="mb-6">
        <p class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">{base_header}</p>
        <h1 class="mt-2 text-2xl font-semibold text-slate-900 dark:text-white">{heading}</h1>
        <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">{detail}</p>
      </div>

      <div class="rounded-xl border px-4 py-3 text-sm {box_classes}">
        <div class="flex items-center gap-2">
          {icon_svg}
          <span>{detail}</span>
        </div>
      </div>

      <div class="mt-6 flex flex-col gap-3">
        <button type="button"
          onclick="window.close();"
          class="w-full rounded-xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-200">
          Close window
        </button>

        <div class="text-center text-xs text-slate-500 dark:text-slate-400">
          Protected by OAuth 2.0 Device Flow
        </div>
      </div>
    </div>
  </div>
</body>
</html>
"#,
        title = title,
        base_header = base_header,
        heading = heading,
        detail = detail,
        box_classes = box_classes,
        icon_svg = icon_svg,
    ))
}
