use anyhow::Result;
use base64::Engine;
use chrono::{DateTime, Duration, TimeZone, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sqlx::{Row, SqlitePool};

use super::config::{Config, SessionBackend};
use super::oidc::{RefreshResult, TokenResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub subject: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowState {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub redirect_url: String,
    pub created_at: DateTime<Utc>,
}

pub enum SessionStore {
    Memory(MemoryStore),
    Sqlite(SqliteStore),
}

impl SessionStore {
    pub async fn new(config: &Config) -> Result<Self> {
        match config.session_backend {
            SessionBackend::Memory => Ok(Self::Memory(MemoryStore::new())),
            SessionBackend::Sqlite => {
                let path = config.session_sqlite_path.as_ref().unwrap();
                Ok(Self::Sqlite(SqliteStore::new(path).await?))
            }
        }
    }

    pub async fn get(&self, session_id: &str) -> Option<Session> {
        match self {
            Self::Memory(store) => store.get(session_id),
            Self::Sqlite(store) => store.get(session_id).await,
        }
    }

    pub async fn create_session(&self, token_response: &TokenResponse, config: &Config) -> String {
        let session_id = generate_session_id();
        let expires_at = Utc::now() + Duration::seconds(config.session_max_age);

        let session = Session {
            session_id: session_id.clone(),
            username: token_response.username.clone(),
            email: token_response.email.clone(),
            groups: token_response.groups.clone(),
            subject: token_response.subject.clone(),
            issued_at: Utc::now(),
            expires_at,
            refresh_token: token_response.refresh_token.clone(),
        };

        match self {
            Self::Memory(store) => store.insert(session),
            Self::Sqlite(store) => store.insert(session).await,
        }

        session_id
    }

    pub async fn delete(&self, session_id: &str) {
        match self {
            Self::Memory(store) => store.delete(session_id),
            Self::Sqlite(store) => store.delete(session_id).await,
        }
    }

    pub async fn store_flow_state(&self, flow_state: &FlowState) {
        match self {
            Self::Memory(store) => store.store_flow_state(flow_state),
            Self::Sqlite(store) => store.store_flow_state(flow_state).await,
        }
    }

    pub async fn get_flow_state(&self, state: &str) -> Option<FlowState> {
        match self {
            Self::Memory(store) => store.get_flow_state(state),
            Self::Sqlite(store) => store.get_flow_state(state).await,
        }
    }

    pub async fn refresh_session(
        &self,
        session_id: &str,
        refresh: &RefreshResult,
        config: &Config,
    ) -> Option<Session> {
        match self {
            Self::Memory(store) => store.refresh_session(session_id, refresh, config),
            Self::Sqlite(store) => store.refresh_session(session_id, refresh, config).await,
        }
    }
}

// Memory store implementation
pub struct MemoryStore {
    sessions: Arc<DashMap<String, Session>>,
    flow_states: Arc<DashMap<String, FlowState>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            flow_states: Arc::new(DashMap::new()),
        }
    }

    pub fn get(&self, session_id: &str) -> Option<Session> {
        self.sessions.get(session_id).map(|entry| entry.clone())
    }

    pub fn insert(&self, session: Session) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    pub fn delete(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn store_flow_state(&self, flow_state: &FlowState) {
        self.flow_states.insert(flow_state.state.clone(), flow_state.clone());
    }

    pub fn get_flow_state(&self, state: &str) -> Option<FlowState> {
        self.flow_states.get(state).map(|entry| entry.clone())
    }

    pub fn refresh_session(
        &self,
        session_id: &str,
        refresh: &RefreshResult,
        config: &Config,
    ) -> Option<Session> {
        let mut entry = self.sessions.get_mut(session_id)?;
        entry.issued_at = Utc::now();
        entry.expires_at = Utc::now() + Duration::seconds(config.session_max_age);
        if refresh.refresh_token.is_some() {
            entry.refresh_token = refresh.refresh_token.clone();
        }
        Some(entry.clone())
    }
}

// SQLite store implementation (stub - can be implemented later)
pub struct SqliteStore {
    #[allow(dead_code)]
    db_path: std::path::PathBuf,
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn new(path: &std::path::Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let db_path = path.to_path_buf();
        let db_url = format!(
            "sqlite://{}",
            db_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid sqlite path"))?
        );

        let pool = SqlitePool::connect(&db_url).await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT,
                groups TEXT NOT NULL,
                subject TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                refresh_token TEXT
            );
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS flow_states (
                state TEXT PRIMARY KEY,
                nonce TEXT NOT NULL,
                pkce_verifier TEXT NOT NULL,
                redirect_url TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(state)
            );
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);")
            .execute(&pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_flow_states_created ON flow_states(created_at);",
        )
        .execute(&pool)
        .await?;

        let columns = sqlx::query("PRAGMA table_info(sessions)")
            .fetch_all(&pool)
            .await?;
        let has_refresh_token = columns.iter().any(|row| {
            let name: String = row.get("name");
            name == "refresh_token"
        });
        if !has_refresh_token {
            let _ = sqlx::query("ALTER TABLE sessions ADD COLUMN refresh_token TEXT")
                .execute(&pool)
                .await;
        }

        Ok(Self { db_path, pool })
    }

    pub async fn get(&self, session_id: &str) -> Option<Session> {
        let row = sqlx::query(
            r#"
            SELECT session_id, username, email, groups, subject, issued_at, expires_at, refresh_token
            FROM sessions
            WHERE session_id = ?
            "#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .ok()??;

        let groups_json: String = row.get("groups");
        let groups = serde_json::from_str(&groups_json).unwrap_or_default();

        let issued_at: i64 = row.get("issued_at");
        let expires_at: i64 = row.get("expires_at");

        Some(Session {
            session_id: row.get("session_id"),
            username: row.get("username"),
            email: row.get("email"),
            groups,
            subject: row.get("subject"),
            issued_at: Utc.timestamp_opt(issued_at, 0).single()?,
            expires_at: Utc.timestamp_opt(expires_at, 0).single()?,
            refresh_token: row.get("refresh_token"),
        })
    }

    pub async fn insert(&self, session: Session) {
        let groups_json = serde_json::to_string(&session.groups).unwrap_or_else(|_| "[]".into());
        let issued_at = session.issued_at.timestamp();
        let expires_at = session.expires_at.timestamp();

        let _ = sqlx::query(
            r#"
            INSERT INTO sessions (session_id, username, email, groups, subject, issued_at, expires_at, refresh_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(session.session_id)
        .bind(session.username)
        .bind(session.email)
        .bind(groups_json)
        .bind(session.subject)
        .bind(issued_at)
        .bind(expires_at)
        .bind(session.refresh_token)
        .execute(&self.pool)
        .await;
    }

    pub async fn delete(&self, session_id: &str) {
        let _ = sqlx::query("DELETE FROM sessions WHERE session_id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await;
    }

    pub async fn store_flow_state(&self, flow_state: &FlowState) {
        let _ = sqlx::query(
            r#"
            INSERT INTO flow_states (state, nonce, pkce_verifier, redirect_url, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&flow_state.state)
        .bind(&flow_state.nonce)
        .bind(&flow_state.pkce_verifier)
        .bind(&flow_state.redirect_url)
        .bind(flow_state.created_at.timestamp())
        .execute(&self.pool)
        .await;
    }

    pub async fn get_flow_state(&self, state: &str) -> Option<FlowState> {
        let row = sqlx::query(
            r#"
            SELECT state, nonce, pkce_verifier, redirect_url, created_at
            FROM flow_states
            WHERE state = ?
            "#,
        )
        .bind(state)
        .fetch_optional(&self.pool)
        .await
        .ok()??;

        let created_at: i64 = row.get("created_at");

        Some(FlowState {
            state: row.get("state"),
            nonce: row.get("nonce"),
            pkce_verifier: row.get("pkce_verifier"),
            redirect_url: row.get("redirect_url"),
            created_at: Utc.timestamp_opt(created_at, 0).single()?,
        })
    }

    pub async fn refresh_session(
        &self,
        session_id: &str,
        refresh: &RefreshResult,
        config: &Config,
    ) -> Option<Session> {
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(config.session_max_age);
        let issued_ts = issued_at.timestamp();
        let expires_ts = expires_at.timestamp();

        let _ = sqlx::query(
            r#"
            UPDATE sessions
            SET issued_at = ?, expires_at = ?, refresh_token = COALESCE(?, refresh_token)
            WHERE session_id = ?
            "#,
        )
        .bind(issued_ts)
        .bind(expires_ts)
        .bind(&refresh.refresh_token)
        .bind(session_id)
        .execute(&self.pool)
        .await;

        self.get(session_id).await
    }
}

fn generate_session_id() -> String {
    use rand::Rng;
    let random_bytes: Vec<u8> = (0..32).map(|_| rand::rng().random()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random_bytes)
}
