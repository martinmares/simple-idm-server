use crate::db::models::OAuthClient;
use axum::http::{HeaderMap, header};
use base64::Engine as _;
use sqlx::PgPool;

pub fn scope_allowed(registered: &str, requested: &str) -> bool {
    if requested.len() > 4096
        || !requested.bytes().all(|byte| {
            byte == b' '
                || byte == 0x21
                || (0x23..=0x5b).contains(&byte)
                || (0x5d..=0x7e).contains(&byte)
        })
    {
        return false;
    }
    requested.split_whitespace().all(|scope| {
        registered
            .split_whitespace()
            .any(|allowed| allowed == scope)
    })
}

pub fn authorization_allowed(
    client: &OAuthClient,
    scope: &str,
    challenge: Option<&str>,
    method: Option<&str>,
) -> bool {
    client
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
        && scope_allowed(&client.scope, scope)
        && match challenge {
            Some(value) => {
                method == Some("S256")
                    && value.len() == 43
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            }
            None => !client.is_public && method.is_none(),
        }
}

pub async fn user_client_allowed(
    pool: &PgPool,
    client_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users u JOIN oauth_clients c ON c.tenant_id = u.tenant_id JOIN tenants t ON t.id = u.tenant_id WHERE u.id = $1 AND c.id = $2 AND u.is_active AND c.is_active AND t.is_active AND u.deleted_at IS NULL AND c.deleted_at IS NULL AND t.deleted_at IS NULL)")
        .bind(user_id).bind(client_id).fetch_one(pool).await
}

#[derive(Debug)]
pub enum ClientLookupError {
    InvalidTenantHint,
    AmbiguousClientId,
    Database,
}

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
        if client_id
            .as_deref()
            .is_some_and(|id| !id.is_empty() && id != basic_id)
            || client_secret
                .as_deref()
                .is_some_and(|secret| !secret.is_empty() && secret != basic_secret)
        {
            *client_id = None;
            *client_secret = None;
            return;
        }
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
    // OAuth Basic credentials are form-encoded before Base64 (RFC 6749 2.3.1).
    let id = parts.next()?.replace('+', " ");
    let secret = parts.next()?.replace('+', " ");
    let client_id = urlencoding::decode(&id).ok()?.into_owned();
    let client_secret = urlencoding::decode(&secret).ok()?.into_owned();
    Some((client_id, client_secret))
}

pub async fn resolve_oauth_client(
    db_pool: &PgPool,
    client_id: &str,
    tenant_hint: Option<&str>,
) -> Result<Option<OAuthClient>, ClientLookupError> {
    if let Some(hint) = tenant_hint.map(str::trim).filter(|h| !h.is_empty()) {
        let client = sqlx::query_as::<_, OAuthClient>(
            r#"
            SELECT oc.*
            FROM oauth_clients oc
            JOIN tenants t ON t.id = oc.tenant_id
            WHERE oc.client_id = $1
              AND oc.is_active = true
              AND oc.deleted_at IS NULL
              AND t.slug = $2
              AND t.is_active = true
              AND t.deleted_at IS NULL
            LIMIT 1
            "#,
        )
        .bind(client_id)
        .bind(hint)
        .fetch_optional(db_pool)
        .await
        .map_err(|_| ClientLookupError::Database)?;

        if client.is_some() {
            return Ok(client);
        }

        let tenant_exists = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM tenants WHERE slug = $1 AND is_active = true AND deleted_at IS NULL LIMIT 1",
        )
        .bind(hint)
        .fetch_optional(db_pool)
        .await
        .map_err(|_| ClientLookupError::Database)?;

        if tenant_exists.is_none() {
            return Err(ClientLookupError::InvalidTenantHint);
        }

        return Ok(None);
    }

    let clients = sqlx::query_as::<_, OAuthClient>(
        r#"
        SELECT oc.*
        FROM oauth_clients oc JOIN tenants t ON t.id = oc.tenant_id
        WHERE oc.client_id = $1 AND oc.is_active = true AND oc.deleted_at IS NULL
          AND t.is_active = true AND t.deleted_at IS NULL
        ORDER BY oc.created_at ASC
        LIMIT 2
        "#,
    )
    .bind(client_id)
    .fetch_all(db_pool)
    .await
    .map_err(|_| ClientLookupError::Database)?;

    match clients.len() {
        0 => Ok(None),
        1 => Ok(clients.into_iter().next()),
        _ => Err(ClientLookupError::AmbiguousClientId),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_client_credentials_decode_form_encoding_once() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD
            .encode("client%3Aone:secret%2B%2F%3A%25+space");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        assert_eq!(
            parse_basic_auth(&headers),
            Some(("client:one".into(), "secret+/:% space".into()))
        );
        let mut id = Some("client:one".into());
        let mut secret = Some("secret+/:% space".into());
        apply_client_auth(&mut id, &mut secret, &headers);
        assert_eq!(id.as_deref(), Some("client:one"));
        assert_eq!(secret.as_deref(), Some("secret+/:% space"));
        headers.insert(header::AUTHORIZATION, "Basic aWQ6JUZG".parse().unwrap());
        assert_eq!(parse_basic_auth(&headers), None);
    }

    #[test]
    fn requested_scopes_must_be_registered_words() {
        assert!(scope_allowed("openid profile email", "email openid"));
        assert!(!scope_allowed("openid profile email", "openid admin:*"));
        assert!(!scope_allowed("groups:read", "groups"));
        assert!(scope_allowed("openid", ""));
    }

    #[tokio::test]
    #[ignore = "requires disposable DATABASE_URL; run scripts/test-postgres.sh"]
    async fn postgres_client_authorization_boundaries() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let mut client = sqlx::query_as::<_, OAuthClient>(
            "SELECT * FROM oauth_clients WHERE client_id = 'cli-tools'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let challenge = "A".repeat(43);
        client.is_public = true;
        assert!(!authorization_allowed(&client, "openid", None, None));
        assert!(!authorization_allowed(
            &client,
            "openid",
            Some(&challenge),
            Some("plain")
        ));
        assert!(authorization_allowed(
            &client,
            "openid",
            Some(&challenge),
            Some("S256")
        ));
        assert!(!authorization_allowed(
            &client,
            "unregistered",
            Some(&challenge),
            Some("S256")
        ));
        client.is_public = false;
        assert!(authorization_allowed(&client, "openid", None, None));
        client.grant_types.clear();
        assert!(!authorization_allowed(&client, "openid", None, None));

        let tenant = uuid::Uuid::new_v4();
        let user = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'Authorization test')")
            .bind(tenant)
            .bind(tenant.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id, tenant_id, username, email, password_hash) VALUES ($1, $2, $3, $4, 'unused')")
            .bind(user).bind(tenant).bind(user.to_string()).bind(format!("{user}@example.test")).execute(&pool).await.unwrap();
        assert!(!user_client_allowed(&pool, client.id, user).await.unwrap());
        sqlx::query("UPDATE users SET tenant_id = (SELECT tenant_id FROM oauth_clients WHERE id = $1) WHERE id = $2")
            .bind(client.id).bind(user).execute(&pool).await.unwrap();
        assert!(user_client_allowed(&pool, client.id, user).await.unwrap());
        sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!user_client_allowed(&pool, client.id, user).await.unwrap());
    }
}
