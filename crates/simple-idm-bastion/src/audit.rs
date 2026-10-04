use crate::config::{Config, Host};
use anyhow::{Result, ensure};
use fs2::FileExt;
use serde::Serialize;
use simple_idm_core::ssh_signer::jwt_validator::TokenClaims;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
pub struct InstanceLock {
    _file: File,
}
impl InstanceLock {
    pub fn acquire(db: &Path) -> Result<Self> {
        // Canonicalize the database first, then lock a persistent sidecar. BSD
        // flock on the database itself conflicts with SQLite's database locks.
        let database = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(db)?;
        drop(database);
        let canonical = db.canonicalize()?;
        let mut lock_path = canonical.into_os_string();
        lock_path.push(".bastion.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(std::path::PathBuf::from(lock_path))?;
        file.try_lock_exclusive()
            .map_err(|e| anyhow::anyhow!("audit database is owned by another instance: {e}"))?;
        Ok(Self { _file: file })
    }
}
#[derive(Clone)]
pub struct Audit {
    pool: SqlitePool,
}
#[derive(Default, clap::Args)]
pub struct Filters {
    #[arg(long)]
    pub subject: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub result: Option<String>,
    /// Inclusive Unix epoch milliseconds.
    #[arg(long)]
    pub since: Option<i64>,
    /// Exclusive Unix epoch milliseconds.
    #[arg(long)]
    pub until: Option<i64>,
}
#[derive(Debug, Serialize)]
pub struct Record {
    pub session_id: String,
    pub bastion_id: String,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub tenant: Option<String>,
    pub username: Option<String>,
    pub host_id: String,
    pub address: Option<String>,
    pub port: Option<i64>,
    pub linux_user: String,
    pub client_ip: String,
    pub requested_at: i64,
    pub connected_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub reconciled_at: Option<i64>,
    pub duration_ms: Option<i64>,
    pub result: String,
    pub end_reason: Option<String>,
    pub exit_status: Option<i64>,
    pub certificate_id: Option<String>,
}
impl Audit {
    pub async fn open(path: &Path, readonly: bool) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(readonly)
            .create_if_missing(false)
            .busy_timeout(std::time::Duration::from_secs(5));
        let options = if readonly {
            options
        } else {
            options
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
        };
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        if !readonly {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&pool)
                .await?;
            ensure!(version <= 1, "audit schema newer than this binary");
            sqlx::raw_sql(include_str!("../migrations/001_sessions.sql"))
                .execute(&pool)
                .await?;
        }
        Ok(Self { pool })
    }
    pub async fn reconcile(&self) -> Result<u64> {
        // Unknown actual end time/duration remain NULL after crash.
        Ok(sqlx::query("UPDATE sessions SET result='interrupted', end_reason='restart_unknown_end', reconciled_at=? WHERE ended_at IS NULL AND reconciled_at IS NULL")
            .bind(now()).execute(&self.pool).await?.rows_affected())
    }
    pub async fn requested(
        &self,
        config: &Config,
        session: &str,
        host: &str,
        login: &str,
        ip: &str,
    ) -> Result<()> {
        sqlx::query("INSERT INTO sessions (session_id,bastion_id,host_id,linux_user,client_ip,requested_at,result) VALUES (?,?,?,?,?,?,'requested')")
            .bind(session).bind(&config.bastion_id).bind(host).bind(login).bind(ip).bind(now()).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn identity(
        &self,
        session: &str,
        claims: &TokenClaims,
        host: Option<&Host>,
    ) -> Result<()> {
        sqlx::query("UPDATE sessions SET issuer=?,subject=?,tenant=?,username=?,address=?,port=? WHERE session_id=?")
            .bind(&claims.iss).bind(&claims.sub).bind(&claims.tenant_id).bind(&claims.preferred_username)
            .bind(host.map(|h| &h.address)).bind(host.map(|h| i64::from(h.port))).bind(session).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn certificate(&self, session: &str, id: &str) -> Result<()> {
        sqlx::query("UPDATE sessions SET certificate_id=? WHERE session_id=?")
            .bind(id)
            .bind(session)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn connected(&self, session: &str) -> Result<()> {
        let rows = sqlx::query("UPDATE sessions SET connected_at=?,result='connected' WHERE session_id=? AND connected_at IS NULL AND ended_at IS NULL AND reconciled_at IS NULL")
            .bind(now()).bind(session).execute(&self.pool).await?.rows_affected();
        ensure!(rows == 1, "session not available for connected audit");
        Ok(())
    }
    pub async fn ended(
        &self,
        session: &str,
        result: &str,
        reason: &str,
        status: Option<i32>,
        duration: Option<i64>,
    ) -> Result<()> {
        // Stable timestamps even when an end write is retried.
        let ended = now();
        for attempt in 0..3 {
            let update = sqlx::query("UPDATE sessions SET ended_at=?,result=?,end_reason=?,exit_status=?,duration_ms=? WHERE session_id=? AND ended_at IS NULL AND reconciled_at IS NULL")
                .bind(ended).bind(result).bind(reason).bind(status).bind(duration).bind(session).execute(&self.pool).await;
            match update {
                Ok(_) => return Ok(()),
                Err(e) => {
                    tracing::error!(session_id=session, attempt, error=%e, "durable audit end write failed");
                    if attempt == 2 {
                        return Err(e.into());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100 * (attempt + 1))).await;
                }
            }
        }
        unreachable!()
    }
    pub async fn retain(&self, days: u32) -> Result<u64> {
        ensure!(days > 0, "retention must be positive");
        Ok(sqlx::query("DELETE FROM sessions WHERE requested_at < ? AND (ended_at IS NOT NULL OR reconciled_at IS NOT NULL)")
            .bind(now() - i64::from(days) * 86_400_000).execute(&self.pool).await?.rows_affected())
    }
    pub async fn records(&self, f: &Filters) -> Result<Vec<Record>> {
        let rows = sqlx::query("SELECT * FROM sessions WHERE (? IS NULL OR subject=?) AND (? IS NULL OR username=?) AND (? IS NULL OR host_id=?) AND (? IS NULL OR result=?) AND (? IS NULL OR requested_at>=?) AND (? IS NULL OR requested_at<?) ORDER BY requested_at,session_id")
            .bind(&f.subject).bind(&f.subject).bind(&f.username).bind(&f.username).bind(&f.host).bind(&f.host).bind(&f.result).bind(&f.result)
            .bind(f.since).bind(f.since).bind(f.until).bind(f.until).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|r| {
                Ok(Record {
                    session_id: r.try_get("session_id")?,
                    bastion_id: r.try_get("bastion_id")?,
                    issuer: r.try_get("issuer")?,
                    subject: r.try_get("subject")?,
                    tenant: r.try_get("tenant")?,
                    username: r.try_get("username")?,
                    host_id: r.try_get("host_id")?,
                    address: r.try_get("address")?,
                    port: r.try_get("port")?,
                    linux_user: r.try_get("linux_user")?,
                    client_ip: r.try_get("client_ip")?,
                    requested_at: r.try_get("requested_at")?,
                    connected_at: r.try_get("connected_at")?,
                    ended_at: r.try_get("ended_at")?,
                    reconciled_at: r.try_get("reconciled_at")?,
                    duration_ms: r.try_get("duration_ms")?,
                    result: r.try_get("result")?,
                    end_reason: r.try_get("end_reason")?,
                    exit_status: r.try_get("exit_status")?,
                    certificate_id: r.try_get("certificate_id")?,
                })
            })
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn crash_and_idempotent_finish_and_filters() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let lock = InstanceLock::acquire(&db).unwrap();
        assert!(InstanceLock::acquire(&db).is_err());
        let alias = dir.path().join("audit-alias.db");
        std::os::unix::fs::symlink(&db, &alias).unwrap();
        assert!(InstanceLock::acquire(&alias).is_err());
        let a = Audit::open(&db, false).await.unwrap();
        let c: Config = toml::from_str(include_str!("../examples/bastion.toml")).unwrap();
        a.requested(&c, "one", "host", "alice", "127.0.0.1")
            .await
            .unwrap();
        a.connected("one").await.unwrap();
        a.ended("one", "exited", "shell_exit", Some(0), Some(42))
            .await
            .unwrap();
        a.ended("one", "failed", "bad", Some(1), Some(99))
            .await
            .unwrap();
        a.requested(&c, "two", "host", "bob", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(a.reconcile().await.unwrap(), 1);
        assert_eq!(a.reconcile().await.unwrap(), 0);
        let rows = a.records(&Filters::default()).await.unwrap();
        assert_eq!(rows[0].duration_ms, Some(42));
        assert_eq!(rows[0].result, "exited");
        assert_eq!(rows[1].result, "interrupted");
        assert!(rows[1].ended_at.is_none());
        assert!(rows[1].duration_ms.is_none());
        assert_eq!(
            a.records(&Filters {
                result: Some("interrupted".into()),
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
            1
        );
        drop(lock);
    }
}
