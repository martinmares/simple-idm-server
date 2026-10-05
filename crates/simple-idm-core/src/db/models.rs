use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub credential_version: i64,
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub is_active: bool,
    pub auth_mode: String, // local|federated|ad
    pub auth_provider_id: Option<Uuid>,
    pub password_disabled: bool, // disable local password login
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub recovery_email: Option<String>,
    pub phone_e164: Option<String>,
    pub last_sign_in_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub slug: String,
    pub provider_type: String,
    pub issuer: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_encrypted: String,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub jwks_url: Option<String>,
    pub scopes: Vec<String>,
    pub hd_domain: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserIdentity {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub idp_id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub email_at_link: Option<String>,
    pub email_verified: Option<bool>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub approval_status: String,
    pub approved_at: Option<DateTime<Utc>>,
    pub rejected_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_virtual: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct UserGroup {
    pub user_id: Uuid,
    pub group_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: Uuid,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_hash: Option<String>, // None for public clients
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
    pub is_active: bool,
    pub is_public: bool, // true for public clients (PKCE-only, no secret)
    pub groups_claim_mode: String,
    pub include_claim_maps: bool,
    pub ignore_virtual_groups: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ClaimMap {
    pub id: Uuid,
    pub client_id: Uuid,
    pub group_id: Option<Uuid>, // Optional - can use patterns instead
    pub claim_name: String,
    pub claim_value: Option<String>,
    pub claim_value_kind: String,         // 'single' or 'array'
    pub claim_value_json: Option<String>, // JSON array for array kind
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub scope: String,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct UsedRefreshToken {
    pub token: String,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub scope: String,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
    pub is_authorized: bool,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuthenticationSession {
    pub credential_version: i64,
    pub id: Uuid,
    pub session_token: String,
    pub user_id: Uuid,
    pub client_id: Option<Uuid>, // Optional client-specific session expiry
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct UserAuthenticator {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub kind: String,
    pub label: String,
    pub secret_encrypted: String,
    pub status: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_step: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserGroupPattern {
    pub id: Uuid,
    pub user_id: Uuid,
    pub pattern: String,
    pub is_include: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OAuthClientGroupPattern {
    pub id: Uuid,
    pub client_id: Uuid,
    pub pattern: String,
    pub is_include: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ClaimMapPattern {
    pub id: Uuid,
    pub claim_map_id: Uuid,
    pub pattern: String,
    pub is_include: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}
