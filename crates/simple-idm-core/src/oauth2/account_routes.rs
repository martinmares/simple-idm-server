//! Browser sign-in for account settings, using the shared password/MFA/passkey flow.
use super::{OAuth2State, authorization_code};
use crate::db::models::OAuthClient;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};

pub(super) const CLIENT_ID: &str = "simple-idm-account";

fn allowed_destination(destination: &str) -> bool {
    matches!(destination, "/account/security" | "/account/mfa")
}

/// This client can create only an IDM browser session, never an OAuth code or token.
pub(super) fn is_account_destination(client: &OAuthClient, destination: &str) -> bool {
    client.client_id == CLIENT_ID
        && client.grant_types.is_empty()
        && client.scope.is_empty()
        && allowed_destination(destination)
        && client.redirect_uris.iter().any(|uri| uri == destination)
}

pub(super) fn sign_in_redirect(destination: &str) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("return_to", destination)
        .finish();
    Redirect::to(&format!("/account/login?{query}")).into_response()
}

#[derive(Deserialize)]
pub struct AccountLoginRequest {
    pub return_to: Option<String>,
    pub tenant: Option<String>,
}

pub async fn login(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    Query(req): Query<AccountLoginRequest>,
) -> Response {
    let destination = req.return_to.as_deref().unwrap_or("/account/security");
    if !allowed_destination(destination) {
        return (
            StatusCode::BAD_REQUEST,
            Html(super::templates::error_page(
                "invalid_request",
                "Invalid account settings destination",
            )),
        )
            .into_response();
    }
    let tenant = req.tenant.as_deref().unwrap_or("default");
    // Created on demand, including for tenants added after installation. No grants are enabled.
    let result = sqlx::query("INSERT INTO oauth_clients (tenant_id,client_id,name,client_secret_hash,is_public,redirect_uris,grant_types,scope) SELECT id,$1,'Simple IDM account settings',NULL,true,ARRAY['/account/security','/account/mfa'],ARRAY[]::text[],'' FROM tenants WHERE (slug = $2 OR id::text = $2) AND is_active AND deleted_at IS NULL ON CONFLICT (tenant_id,client_id) DO NOTHING")
        .bind(CLIENT_ID).bind(tenant).execute(&state.db_pool).await;
    if let Err(err) = result {
        tracing::error!("Could not prepare account sign-in: {err}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(super::templates::error_page(
                "server_error",
                "Could not prepare account sign-in",
            )),
        )
            .into_response();
    }
    let params = HashMap::from([
        ("response_type".into(), "code".into()),
        ("client_id".into(), CLIENT_ID.into()),
        ("redirect_uri".into(), destination.into()),
        ("scope".into(), String::new()),
        ("tenant".into(), tenant.into()),
    ]);
    authorization_code::handle_authorize(State(state), headers, Query(params))
        .await
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_destinations_are_fixed_local_paths() {
        assert!(allowed_destination("/account/mfa"));
        assert!(allowed_destination("/account/security"));
        for path in [
            "https://evil.test",
            "//evil.test",
            "/account/mfa?next=https://evil.test",
            "/oauth2/token",
            "/account/security/../logout",
        ] {
            assert!(!allowed_destination(path));
        }
        let response = sign_in_redirect("/account/mfa");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()["location"],
            "/account/login?return_to=%2Faccount%2Fmfa"
        );
    }

    #[tokio::test]
    #[ignore = "requires disposable DATABASE_URL; run scripts/test-postgres.sh"]
    async fn postgres_account_sign_in_enrollment_and_admin_reset() {
        use super::super::authorization_code::{
            LoginRequest, MfaCodeRequest, get_auth_session_from_cookie, handle_login, handle_mfa,
            show_mfa_form,
        };
        use axum::{Form, http::header};
        use rsa::{
            RsaPrivateKey, RsaPublicKey,
            pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
            rand_core::OsRng,
        };
        use uuid::Uuid;
        async fn body(response: Response) -> String {
            String::from_utf8(
                axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        }
        fn cookie(response: &Response, name: &str) -> String {
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find_map(|v| {
                    v.strip_prefix(&format!("{name}="))
                        .map(|v| v.split(';').next().unwrap().to_owned())
                })
                .unwrap()
        }
        fn headers(name: &str, value: &str) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, format!("{name}={value}").parse().unwrap());
            headers
        }
        fn request(username: &str, csrf: &str) -> LoginRequest {
            LoginRequest {
                username: username.into(),
                password: "account-test-password".into(),
                client_id: CLIENT_ID.into(),
                tenant: Some("default".into()),
                redirect_uri: "/account/mfa".into(),
                scope: Some(String::new()),
                state: None,
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
                csrf_token: Some(csrf.into()),
            }
        }
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let private = dir.path().join("private.pem");
        let public = dir.path().join("public.pem");
        std::fs::write(
            &private,
            key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::write(
            &public,
            RsaPublicKey::from(&key)
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        let jwt = crate::auth::JwtService::new(
            private.to_str().unwrap(),
            public.to_str().unwrap(),
            "https://idm.test".into(),
            "test".into(),
            vec![],
        )
        .unwrap();
        let state = Arc::new(OAuth2State {
            db_pool: pool.clone(),
            jwt_service: Arc::new(jwt),
            access_token_expiry: 3600,
            refresh_token_expiry: 3600,
            auth_session_expiry: 3600,
            allow_username_login: true,
            allowed_email_domains: vec![],
            trust_proxy_headers: false,
            force_secure_cookies: false,
            passkeys: None,
            device_flow_config: crate::config::DeviceFlowConfig {
                expiry_seconds: 600,
                polling_interval_seconds: 1,
                user_code_length: 8,
                user_code_format: "XXXX-XXXX".into(),
                cleanup_interval_seconds: 60,
                max_verification_attempts: 5,
            },
            auth_protection: crate::config::AuthProtectionConfig {
                enabled: false,
                failure_window_seconds: 60,
                max_failures: 5,
                lockout_seconds: 60,
                clear_on_start: false,
            },
        });
        let user = Uuid::new_v4();
        let username = format!("account-{}", user.simple());
        let password = crate::auth::hash_password("account-test-password").unwrap();
        sqlx::query("INSERT INTO users (id,username,email,password_hash) VALUES ($1,$2,$3,$4)")
            .bind(user)
            .bind(&username)
            .bind(format!("{user}@example.test"))
            .bind(password)
            .execute(&pool)
            .await
            .unwrap();
        let previous_policy: String =
            sqlx::query_scalar("SELECT mfa_policy FROM tenants WHERE slug='default'")
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("UPDATE tenants SET mfa_policy='required' WHERE slug='default'")
            .execute(&pool)
            .await
            .unwrap();

        // Direct settings links begin browser sign-in, including when passkeys are disabled.
        for response in [
            super::super::mfa_account_routes::settings(State(state.clone()), HeaderMap::new())
                .await,
            super::super::passkey_routes::security_page(State(state.clone()), HeaderMap::new())
                .await,
        ] {
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert!(
                response.headers()[header::LOCATION]
                    .to_str()
                    .unwrap()
                    .starts_with("/account/login?")
            );
        }
        let page = login(
            State(state.clone()),
            HeaderMap::new(),
            Query(AccountLoginRequest {
                return_to: Some("/account/mfa".into()),
                tenant: None,
            }),
        )
        .await;
        let csrf = cookie(&page, "csrf_token");
        assert!(body(page).await.contains("name=\"password\""));
        let client = super::super::utils::resolve_oauth_client(&pool, CLIENT_ID, Some("default"))
            .await
            .unwrap()
            .unwrap();
        assert!(!super::super::utils::authorization_allowed(
            &client, "", None, None
        ));
        assert!(
            !authorization_code::is_login_destination_allowed(&pool, &client, "https://evil.test")
                .await
        );

        let response = handle_login(
            State(state.clone()),
            headers("csrf_token", &csrf),
            Form(request(&username, &csrf)),
        )
        .await
        .into_response();
        assert_eq!(response.headers()[header::LOCATION], "/oauth2/mfa");
        assert!(
            !response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().unwrap().starts_with("auth_session="))
        );
        let transaction = cookie(&response, "mfa_transaction");
        let page = show_mfa_form(
            State(state.clone()),
            headers("mfa_transaction", &transaction),
        )
        .await
        .into_response();
        assert!(body(page).await.contains("Manual setup key"));
        let rejected = handle_mfa(
            State(state.clone()),
            headers("mfa_transaction", &transaction),
            Form(MfaCodeRequest {
                code: "invalid".into(),
            }),
        )
        .await;
        assert!(
            !rejected
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().unwrap().starts_with("auth_session="))
        );
        assert!(
            crate::mfa::active_totp_authenticator(&pool, user)
                .await
                .unwrap()
                .is_none()
        );
        let pending = crate::mfa::pending_totp_authenticator(&pool, user)
            .await
            .unwrap()
            .unwrap();
        let secret = crate::secret_crypto::decrypt_secret(&pending.secret_encrypted).unwrap();
        let decoded = totp_rs::Secret::try_from_base32(&secret).unwrap();
        let totp = totp_rs::Builder::new()
            .with_secret(decoded.as_bytes())
            .with_account_name("test")
            .with_issuer(Some("Simple IDM"))
            .build()
            .unwrap();
        let response = handle_mfa(
            State(state.clone()),
            headers("mfa_transaction", &transaction),
            Form(MfaCodeRequest {
                code: totp.generate_current().to_string(),
            }),
        )
        .await;
        let session = cookie(&response, "auth_session");
        let page = body(response).await;
        assert!(page.contains("recovery"));
        assert!(page.contains("href=\"/account/mfa\""));
        assert!(!page.contains("?code="));
        let session_headers = headers("auth_session", &session);
        assert!(
            get_auth_session_from_cookie(&pool, &session_headers)
                .await
                .is_some()
        );
        let page = super::super::mfa_account_routes::settings(
            State(state.clone()),
            session_headers.clone(),
        )
        .await;
        assert!(body(page).await.contains("Authenticator app is active"));
        let codes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM authorization_codes WHERE user_id=$1")
                .bind(user)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(codes, 0);

        // Reset removes the factor/recovery codes and invalidates SSO; next password login enrolls again.
        assert!(crate::mfa::admin_reset_user_mfa(&pool, user).await.unwrap());
        assert!(
            get_auth_session_from_cookie(&pool, &session_headers)
                .await
                .is_none()
        );
        assert!(
            crate::mfa::active_totp_authenticator(&pool, user)
                .await
                .unwrap()
                .is_none()
        );
        let recovery: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=$1")
                .bind(user)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(recovery, 0);
        let response = handle_login(
            State(state.clone()),
            headers("csrf_token", &csrf),
            Form(request(&username, &csrf)),
        )
        .await
        .into_response();
        let transaction = cookie(&response, "mfa_transaction");
        let page = show_mfa_form(State(state), headers("mfa_transaction", &transaction))
            .await
            .into_response();
        assert!(body(page).await.contains("Manual setup key"));
        let replacement = crate::mfa::pending_totp_authenticator(&pool, user)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(replacement.id, pending.id);
        assert_ne!(
            crate::secret_crypto::decrypt_secret(&replacement.secret_encrypted).unwrap(),
            secret
        );
        sqlx::query("UPDATE tenants SET mfa_policy=$1 WHERE slug='default'")
            .bind(previous_policy)
            .execute(&pool)
            .await
            .unwrap();
    }
}
