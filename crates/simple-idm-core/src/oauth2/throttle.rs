use crate::config::AuthProtectionConfig;
use crate::db::DbPool;
use axum::http::HeaderMap;
use chrono::Utc;
use sqlx::Row;

pub fn extract_client_ip(headers: &HeaderMap, trust_proxy_headers: bool) -> Option<String> {
    if !trust_proxy_headers {
        return None;
    }
    if trust_proxy_headers {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            return Some(ip.to_string());
        }
    }

    headers
        .get("x-real-ip")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
}

pub async fn is_locked(
    db_pool: &DbPool,
    endpoint: &str,
    identity_key: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT locked_until FROM auth_throttle WHERE endpoint = $1 AND identity_key = $2",
    )
    .bind(endpoint)
    .bind(identity_key)
    .fetch_optional(db_pool)
    .await?;

    if let Some(row) = row {
        let locked_until: Option<chrono::DateTime<Utc>> = row.try_get("locked_until")?;
        if let Some(locked_until) = locked_until {
            return Ok(locked_until > Utc::now());
        }
    }

    Ok(false)
}

pub async fn register_failure(
    db_pool: &DbPool,
    endpoint: &str,
    identity_key: &str,
    cfg: &AuthProtectionConfig,
) -> Result<(), sqlx::Error> {
    if !cfg.enabled {
        return Ok(());
    }

    sqlx::query(r#"
        INSERT INTO auth_throttle (endpoint, identity_key, failures, window_started_at, last_failed_at, locked_until)
        VALUES ($1, $2, 1, NOW(), NOW(), CASE WHEN $4 <= 1 THEN NOW() + make_interval(secs => $5) ELSE NULL END)
        ON CONFLICT (endpoint, identity_key) DO UPDATE SET
            failures = CASE WHEN auth_throttle.window_started_at < NOW() - make_interval(secs => $3)
                THEN 1 ELSE auth_throttle.failures + 1 END,
            window_started_at = CASE WHEN auth_throttle.window_started_at < NOW() - make_interval(secs => $3)
                THEN NOW() ELSE auth_throttle.window_started_at END,
            last_failed_at = NOW(),
            locked_until = CASE WHEN (CASE WHEN auth_throttle.window_started_at < NOW() - make_interval(secs => $3)
                THEN 1 ELSE auth_throttle.failures + 1 END) >= $4
                THEN NOW() + make_interval(secs => $5) ELSE auth_throttle.locked_until END
    "#)
    .bind(endpoint).bind(identity_key).bind(cfg.failure_window_seconds as f64)
    .bind(cfg.max_failures).bind(cfg.lockout_seconds as f64).execute(db_pool).await?;

    Ok(())
}

pub async fn clear_failures(
    db_pool: &DbPool,
    endpoint: &str,
    identity_key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM auth_throttle WHERE endpoint = $1 AND identity_key = $2")
        .bind(endpoint)
        .bind(identity_key)
        .execute(db_pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forwarded_addresses_are_ignored_without_proxy_trust() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.1".parse().unwrap());
        headers.insert("x-forwarded-for", "198.51.100.2".parse().unwrap());
        assert_eq!(extract_client_ip(&headers, false), None);
    }
    #[tokio::test]
    #[ignore = "requires disposable DATABASE_URL; run scripts/test-postgres.sh"]
    async fn postgres_concurrent_failures_are_counted_atomically() {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let key = uuid::Uuid::new_v4().to_string();
        let cfg = AuthProtectionConfig {
            enabled: true,
            failure_window_seconds: 300,
            max_failures: 5,
            lockout_seconds: 300,
            clear_on_start: false,
        };
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let pool = pool.clone();
            let key = key.clone();
            let cfg = cfg.clone();
            tasks.push(tokio::spawn(async move {
                register_failure(&pool, "regression", &key, &cfg)
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let count: i32 = sqlx::query_scalar("SELECT failures FROM auth_throttle WHERE endpoint = 'regression' AND identity_key = $1").bind(&key).fetch_one(&pool).await.unwrap();
        assert_eq!(count, 20);
        assert!(is_locked(&pool, "regression", &key).await.unwrap());
        clear_failures(&pool, "regression", &key).await.unwrap();
        assert!(!is_locked(&pool, "regression", &key).await.unwrap());
    }
}
