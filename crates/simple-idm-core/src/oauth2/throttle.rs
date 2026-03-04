use crate::config::AuthProtectionConfig;
use crate::db::DbPool;
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use sqlx::Row;

pub fn extract_client_ip(headers: &HeaderMap, trust_proxy_headers: bool) -> Option<String> {
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

    let now = Utc::now();
    let row = sqlx::query(
        r#"
        SELECT failures, window_started_at
        FROM auth_throttle
        WHERE endpoint = $1 AND identity_key = $2
        "#,
    )
    .bind(endpoint)
    .bind(identity_key)
    .fetch_optional(db_pool)
    .await?;

    let (mut failures, mut window_started_at) = if let Some(row) = row {
        (
            row.try_get::<i32, _>("failures")?,
            row.try_get::<chrono::DateTime<Utc>, _>("window_started_at")?,
        )
    } else {
        (0, now)
    };

    if now - window_started_at > Duration::seconds(cfg.failure_window_seconds) {
        failures = 0;
        window_started_at = now;
    }

    failures += 1;
    let locked_until = if failures >= cfg.max_failures {
        Some(now + Duration::seconds(cfg.lockout_seconds))
    } else {
        None
    };

    sqlx::query(
        r#"
        INSERT INTO auth_throttle (endpoint, identity_key, failures, window_started_at, last_failed_at, locked_until)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (endpoint, identity_key)
        DO UPDATE SET
            failures = EXCLUDED.failures,
            window_started_at = EXCLUDED.window_started_at,
            last_failed_at = EXCLUDED.last_failed_at,
            locked_until = EXCLUDED.locked_until
        "#,
    )
    .bind(endpoint)
    .bind(identity_key)
    .bind(failures)
    .bind(window_started_at)
    .bind(now)
    .bind(locked_until)
    .execute(db_pool)
    .await?;

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
