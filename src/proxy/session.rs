use anyhow::Result;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::config::{Config, SessionBackend};
use super::oidc::TokenResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub subject: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
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
}

// SQLite store implementation (stub - can be implemented later)
pub struct SqliteStore {
    #[allow(dead_code)]
    db_path: std::path::PathBuf,
}

impl SqliteStore {
    pub async fn new(path: &std::path::Path) -> Result<Self> {
        // TODO: Initialize SQLite database and create tables
        Ok(Self {
            db_path: path.to_path_buf(),
        })
    }

    pub async fn get(&self, _session_id: &str) -> Option<Session> {
        // TODO: Implement SQLite query
        None
    }

    pub async fn insert(&self, _session: Session) {
        // TODO: Implement SQLite insert
    }

    pub async fn delete(&self, _session_id: &str) {
        // TODO: Implement SQLite delete
    }

    pub async fn store_flow_state(&self, _flow_state: &FlowState) {
        // TODO: Implement SQLite insert
    }

    pub async fn get_flow_state(&self, _state: &str) -> Option<FlowState> {
        // TODO: Implement SQLite query
        None
    }
}

fn generate_session_id() -> String {
    use rand::Rng;
    let random_bytes: Vec<u8> = (0..32).map(|_| rand::rng().random()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random_bytes)
}
