use askama::Template;
use axum::{
    Router,
    extract::{Form, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, NaiveDateTime, Utc};
use rand::RngExt;
use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde_json::json;
use sha2::Digest;
use simple_idm_common::embedded_asset_response;
use simple_idm_core::{
    admin::middleware::AdminAuth,
    db::{DbPool, models::User},
    oauth2::{self, OAuth2State},
    secret_crypto::{decrypt_secret, encrypt_secret},
};
use sqlx::{FromRow, Row};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

const ADMIN_SESSION_COOKIE: &str = "sidm_admin_session";
const ADMIN_SESSION_TTL_SECONDS: i64 = 8 * 60 * 60;

#[derive(Debug, Clone)]
struct WebAdminBranding {
    brand_name: String,
    brand_domain: Option<String>,
    page_title: String,
}

impl Default for WebAdminBranding {
    fn default() -> Self {
        Self {
            brand_name: "Cloud App".to_string(),
            brand_domain: None,
            page_title: "Simple IDM".to_string(),
        }
    }
}

static WEB_ADMIN_BRANDING: OnceLock<WebAdminBranding> = OnceLock::new();
static AUTH_THROTTLE_CLEAR_ON_START: OnceLock<bool> = OnceLock::new();

pub fn set_branding_from_config(
    brand_name: String,
    brand_domain: Option<String>,
    page_title: String,
) {
    let _ = WEB_ADMIN_BRANDING.set(WebAdminBranding {
        brand_name,
        brand_domain,
        page_title,
    });
}

pub fn set_auth_throttle_clear_on_start(enabled: bool) {
    let _ = AUTH_THROTTLE_CLEAR_ON_START.set(enabled);
}

fn web_admin_branding() -> &'static WebAdminBranding {
    WEB_ADMIN_BRANDING.get_or_init(WebAdminBranding::default)
}

fn auth_throttle_clear_on_start_warning() -> Option<String> {
    if *AUTH_THROTTLE_CLEAR_ON_START.get_or_init(|| false) {
        Some(
            "SECURITY WARNING: AUTH_THROTTLE_CLEAR_ON_START=true. Authentication throttle records are cleared on every server startup. Disable this outside temporary development or recovery work."
                .to_string(),
        )
    } else {
        None
    }
}

fn admin_brand_label() -> String {
    let branding = web_admin_branding();
    match &branding.brand_domain {
        Some(domain) if !domain.trim().is_empty() => {
            format!("{} · {}", branding.brand_name, domain.trim())
        }
        _ => branding.brand_name.clone(),
    }
}

fn admin_page_title() -> String {
    web_admin_branding().page_title.clone()
}

fn admin_product_title() -> String {
    format!("{} Admin", admin_page_title())
}

trait AdminTemplateBranding {
    fn admin_brand_label(&self) -> String {
        admin_brand_label()
    }

    fn admin_page_title(&self) -> String {
        admin_page_title()
    }

    fn admin_product_title(&self) -> String {
        admin_product_title()
    }

    fn admin_security_warning(&self) -> Option<String> {
        auth_throttle_clear_on_start_warning()
    }
}

impl<T> AdminTemplateBranding for T {}

#[derive(Clone)]
pub struct WebAdminState {
    pub db_pool: DbPool,
    pub oauth_state: Arc<OAuth2State>,
    pub admin_auth: AdminAuth,
    pub secure_cookies: bool,
    pub ad_onboarding_token_ttl_seconds: i64,
    pub federated_invitation_token_ttl_seconds: i64,
    pub admin_sessions: Arc<RwLock<HashMap<String, (String, DateTime<Utc>)>>>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    token: String,
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserCreateForm {
    username: String,
    email: String,
    password: Option<String>,
    auth_mode: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_uuid")]
    auth_provider_id: Option<Uuid>,
    is_active: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    recovery_email: Option<String>,
    phone_e164: Option<String>,
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserUpdateForm {
    email: String,
    password: Option<String>,
    auth_mode: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_uuid")]
    auth_provider_id: Option<Uuid>,
    is_active: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    recovery_email: Option<String>,
    phone_e164: Option<String>,
    note: Option<String>,
}

fn deserialize_optional_uuid<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(raw) => Uuid::parse_str(raw).map(Some).map_err(de::Error::custom),
    }
}

#[derive(Debug, Deserialize)]
pub struct UserAdMappingsApplyForm {
    mappings_json: String,
}

#[derive(Debug, Deserialize)]
pub struct PatternCreateForm {
    pattern: String,
    mode: String,
    priority: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct PatternUpdateForm {
    pattern: String,
    mode: String,
    priority: Option<i32>,
}

#[derive(Debug, Clone)]
struct ImportedCsvUser {
    first_name: Option<String>,
    last_name: Option<String>,
    email: String,
    recovery_email: Option<String>,
    phone: Option<String>,
    last_sign_in_at: Option<DateTime<Utc>>,
    is_active: bool,
}

#[derive(Debug, Deserialize)]
pub struct GroupCreateForm {
    name: String,
    description: String,
    is_virtual: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroupUpdateForm {
    name: String,
    description: String,
    is_virtual: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroupReparentForm {
    parent_group_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TenantUpdateForm {
    name: String,
    mode: String,
    mfa_policy: String,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TenantDomainCreateForm {
    tenant_id: Uuid,
    domain: String,
    is_primary: Option<String>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TenantDomainUpdateForm {
    domain: String,
    is_primary: Option<String>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MembershipsQuery {
    message: Option<String>,
    error: Option<String>,
    user_id: Option<Uuid>,
    group_id: Option<Uuid>,
    user_filter: Option<String>,
    group_filter: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MembershipAddGroupsForm {
    group_ids_csv: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MembershipAddUsersForm {
    user_ids_csv: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MembershipRemoveGroupsForm {
    group_ids_csv: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MembershipRemoveUsersForm {
    user_ids_csv: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityProviderCreateForm {
    slug: String,
    provider_type: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    auth_url: Option<String>,
    token_url: Option<String>,
    jwks_url: Option<String>,
    scope_openid: Option<String>,
    scope_profile: Option<String>,
    scope_email: Option<String>,
    hd_domain: Option<String>,
    ad_host: Option<String>,
    ad_port: Option<i32>,
    ad_base_dn: Option<String>,
    ad_user_filter: Option<String>,
    ad_tls_mode: Option<String>,
    ad_timeout_seconds: Option<i64>,
    ad_allow_insecure: Option<String>,
    ad_domains: Option<String>,
    ad_bind_dn: Option<String>,
    ad_bind_password: Option<String>,
    ad_role_sync_enabled: Option<String>,
    ad_role_sync_ttl_seconds: Option<i64>,
    ad_role_sync_timeout_seconds: Option<i64>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityProviderUpdateForm {
    slug: String,
    provider_type: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    auth_url: Option<String>,
    token_url: Option<String>,
    jwks_url: Option<String>,
    scope_openid: Option<String>,
    scope_profile: Option<String>,
    scope_email: Option<String>,
    hd_domain: Option<String>,
    ad_host: Option<String>,
    ad_port: Option<i32>,
    ad_base_dn: Option<String>,
    ad_user_filter: Option<String>,
    ad_tls_mode: Option<String>,
    ad_timeout_seconds: Option<i64>,
    ad_allow_insecure: Option<String>,
    ad_domains: Option<String>,
    ad_bind_dn: Option<String>,
    ad_bind_password: Option<String>,
    ad_role_sync_enabled: Option<String>,
    ad_role_sync_ttl_seconds: Option<i64>,
    ad_role_sync_timeout_seconds: Option<i64>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FederatedInvitationForm {
    idp_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct ClientCreateForm {
    client_id: String,
    client_secret: Option<String>,
    name: String,
    redirect_uris: String,
    #[serde(default, deserialize_with = "deserialize_string_or_seq")]
    grant_types: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_seq")]
    scopes: Vec<String>,
    grant_types_csv: Option<String>,
    scope: Option<String>,
    grant_authorization_code: Option<String>,
    grant_refresh_token: Option<String>,
    grant_client_credentials: Option<String>,
    grant_device_code: Option<String>,
    scope_openid: Option<String>,
    scope_profile: Option<String>,
    scope_email: Option<String>,
    scope_groups: Option<String>,
    scope_offline_access: Option<String>,
    groups_claim_mode: Option<String>,
    include_claim_maps: Option<String>,
    ignore_virtual_groups: Option<String>,
    is_public: Option<String>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientUpdateForm {
    client_id: String,
    client_secret: Option<String>,
    name: String,
    redirect_uris: String,
    #[serde(default, deserialize_with = "deserialize_string_or_seq")]
    grant_types: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_seq")]
    scopes: Vec<String>,
    grant_types_csv: Option<String>,
    scope: Option<String>,
    grant_authorization_code: Option<String>,
    grant_refresh_token: Option<String>,
    grant_client_credentials: Option<String>,
    grant_device_code: Option<String>,
    scope_openid: Option<String>,
    scope_profile: Option<String>,
    scope_email: Option<String>,
    scope_groups: Option<String>,
    scope_offline_access: Option<String>,
    groups_claim_mode: Option<String>,
    include_claim_maps: Option<String>,
    ignore_virtual_groups: Option<String>,
    is_public: Option<String>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClaimMapCreateForm {
    client_id: String,
    group_id: Option<String>,
    claim_name: String,
    claim_value: String,
    claim_value_kind: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimMapUpdateForm {
    claim_name: String,
    claim_value: String,
    claim_value_kind: String,
}

#[derive(Debug, Deserialize)]
pub struct AdOnboardingForm {
    token: String,
    login: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    message: Option<String>,
    error: Option<String>,
    next: Option<String>,
    ad_link: Option<String>,
    federated_link: Option<String>,
    q: Option<String>,
    status: Option<String>,
    note: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_string_or_seq")]
    letters: Option<Vec<String>>,
    page: Option<u32>,
    client_id: Option<Uuid>,
    group_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    message: Option<String>,
    error: Option<String>,
    action: Option<String>,
    resource_type: Option<String>,
    outcome: Option<String>,
    q: Option<String>,
    range: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdTokenBulkDeleteForm {
    token_hashes_csv: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdOnboardingQuery {
    token: Option<String>,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FederatedOnboardingQuery {
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdRolesQuery {
    message: Option<String>,
    error: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
struct AdOnboardingTokenRow {
    token_hash: String,
    username: String,
    email: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
struct FederatedInvitationResolvedRow {
    user_id: Uuid,
    tenant_id: Uuid,
    email: String,
    is_active: bool,
    auth_mode: String,
    idp_id: Uuid,
    provider_slug: String,
    provider_type: String,
    issuer: String,
    client_id: String,
    client_secret_encrypted: String,
    auth_url: Option<String>,
    token_url: Option<String>,
    scopes: Vec<String>,
    hd_domain: Option<String>,
    token_hash: String,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct FederatedInviteStatePayload {
    csrf: String,
    token_hash: String,
    provider_slug: String,
}

#[derive(Debug, Deserialize)]
struct FederatedDiscoveryResponse {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FederatedTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct FederatedUserInfoResponse {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
}

#[derive(Debug, Clone, FromRow)]
struct UserAdRoleRow {
    role_name: String,
}

#[derive(Debug, Clone, FromRow)]
struct SimpleGroupOption {
    id: Uuid,
    name: String,
}

#[derive(Debug, Clone)]
struct UserAdMappingModalData {
    user_id: Uuid,
    ad_roles: Vec<UserAdRoleRow>,
    groups: Vec<SimpleGroupOption>,
    existing_mappings_json: String,
}

#[derive(Debug, Clone, FromRow)]
struct ExistingAdMappingRow {
    id: Uuid,
    tenant_id: Uuid,
    idp_id: Option<Uuid>,
    external_role: String,
    group_id: Uuid,
    group_name: String,
    priority: i32,
}

#[derive(Debug, Clone, FromRow)]
struct ExternalRoleRow {
    email: String,
    source: String,
    role_name: String,
    synced_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
struct ExternalRoleMappingRow {
    id: Uuid,
    source: String,
    external_role: String,
    group_name: String,
    mode: String,
    priority: i32,
    is_active: bool,
}

#[derive(Debug, Deserialize)]
struct RoleMappingCreateForm {
    source: String,
    external_role: String,
    group_id: String,
    mode: String,
    priority: Option<i32>,
}

#[derive(Debug, Clone, FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    recovery_email: Option<String>,
    phone_e164: Option<String>,
    last_sign_in_at: Option<DateTime<Utc>>,
    note: Option<String>,
    auth_mode: String,
    auth_provider_id: Option<Uuid>,
    auth_provider_slug: Option<String>,
    is_active: bool,
    external_user_id: Option<String>,
    external_user_id_type: Option<String>,
    external_login_name: Option<String>,
    external_upn: Option<String>,
    external_last_seen_at: Option<DateTime<Utc>>,
    federated_provider_slug: Option<String>,
    federated_provider_type: Option<String>,
    federated_subject: Option<String>,
    federated_approval_status: Option<String>,
    mfa_status: String,
    recovery_codes_remaining: i64,
}

impl UserRow {
    fn is_auth_provider(&self, id: &Uuid) -> bool {
        self.auth_provider_id.as_ref() == Some(id)
    }
}

#[derive(Debug, Clone, FromRow)]
struct UserGroupPatternRow {
    id: Uuid,
    pattern: String,
    is_include: bool,
    priority: i32,
}

#[derive(Debug, Clone, FromRow)]
struct GroupRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    is_virtual: bool,
}

#[derive(Debug, Clone)]
struct GroupTreeRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    is_virtual: bool,
    depth: usize,
    parent_id: Option<Uuid>,
}

impl GroupTreeRow {
    fn indent_px(&self) -> usize {
        self.depth * 22
    }

    fn branch_px(&self) -> usize {
        self.depth * 10
    }
}

#[derive(Debug, Clone, FromRow)]
struct TenantRow {
    id: Uuid,
    slug: String,
    name: String,
    mode: String,
    is_active: bool,
    mfa_policy: String,
    users_count: i64,
    groups_count: i64,
    clients_count: i64,
    domains_count: i64,
}

#[derive(Debug, Clone, FromRow)]
struct TenantDomainRow {
    id: Uuid,
    tenant_slug: String,
    tenant_name: String,
    domain: String,
    is_primary: bool,
    is_active: bool,
}

#[derive(Debug, Clone, FromRow)]
struct IdentityProviderRow {
    id: Uuid,
    slug: String,
    provider_type: String,
    issuer: String,
    client_id: String,
    auth_url: Option<String>,
    token_url: Option<String>,
    jwks_url: Option<String>,
    scopes: Vec<String>,
    hd_domain: Option<String>,
    is_active: bool,
    ad_host: Option<String>,
    ad_port: Option<i32>,
    ad_base_dn: Option<String>,
    ad_user_filter: Option<String>,
    ad_tls_mode: Option<String>,
    ad_timeout_seconds: Option<i64>,
    ad_allow_insecure: Option<bool>,
    ad_domains: Option<Vec<String>>,
    ad_bind_dn: Option<String>,
    ad_role_sync_enabled: Option<bool>,
    ad_role_sync_ttl_seconds: Option<i64>,
    ad_role_sync_timeout_seconds: Option<i64>,
}

impl IdentityProviderRow {
    fn scopes_csv(&self) -> String {
        self.scopes.join(", ")
    }

    fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    fn ad_domains_csv(&self) -> String {
        self.ad_domains
            .as_ref()
            .map(|v| v.join(", "))
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, FromRow)]
struct ClientRow {
    id: Uuid,
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scope: String,
    is_active: bool,
    is_public: bool,
    groups_claim_mode: String,
    include_claim_maps: bool,
    ignore_virtual_groups: bool,
}

impl ClientRow {
    fn has_grant(&self, grant: &str) -> bool {
        self.grant_types.iter().any(|g| g == grant)
    }

    fn has_scope(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }
}

#[derive(Debug, Clone, FromRow)]
struct ClientGroupPatternRow {
    id: Uuid,
    client_id: Uuid,
    pattern: String,
    is_include: bool,
    priority: i32,
}

#[derive(Debug, Clone, FromRow)]
struct ClaimMapRow {
    id: Uuid,
    client_id: Uuid,
    group_id: Option<Uuid>,
    client_name: String,
    group_name: Option<String>,
    claim_name: String,
    claim_value: Option<String>,
    claim_value_json: Option<String>,
    claim_value_kind: String,
}

impl ClaimMapRow {
    fn claim_value_display(&self) -> String {
        if self.claim_value_kind == "array" {
            return self.claim_value_array_values().join(", ");
        }
        self.claim_value.clone().unwrap_or_default()
    }

    fn claim_value_array_csv(&self) -> String {
        if self.claim_value_kind == "array" {
            return self.claim_value_array_values().join("\n");
        }
        self.claim_value.clone().unwrap_or_default()
    }

    fn claim_value_array_values(&self) -> Vec<String> {
        self.claim_value_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<Vec<String>>(json).ok())
            .unwrap_or_default()
    }

    fn group_scope(&self) -> String {
        self.group_name.clone().unwrap_or_else(|| "*".to_string())
    }
}

#[derive(Debug, Clone, FromRow)]
struct UserGroupRow {
    user_id: Uuid,
    username: String,
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    auth_mode: String,
    is_active: bool,
    group_id: Uuid,
    group_name: String,
    group_description: Option<String>,
    group_is_virtual: bool,
}

#[derive(Debug, Clone)]
struct MembershipUserOption {
    id: Uuid,
    username: String,
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    auth_mode: String,
    is_active: bool,
    selected: bool,
}

#[derive(Debug, Clone, FromRow)]
struct MembershipUserRecord {
    id: Uuid,
    username: String,
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    auth_mode: String,
    is_active: bool,
}

#[derive(Debug, Clone)]
struct MembershipGroupOption {
    id: Uuid,
    name: String,
    description: Option<String>,
    is_virtual: bool,
    selected: bool,
}

#[derive(Debug, Clone, FromRow)]
struct MembershipGroupRecord {
    id: Uuid,
    name: String,
    description: Option<String>,
    is_virtual: bool,
}

#[derive(Debug, Clone)]
struct UserAssignedGroupRow {
    ordinal: usize,
    id: Uuid,
    name: String,
    description: Option<String>,
    is_virtual: bool,
}

#[derive(Debug, Clone)]
struct GroupAssignedUserRow {
    ordinal: usize,
    id: Uuid,
    username: String,
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    auth_mode: String,
    is_active: bool,
}

#[derive(Debug, Clone)]
struct ClientClaimsRow {
    id: Uuid,
    name: String,
    selected: bool,
    claims_count: usize,
}

#[derive(Debug, Clone)]
struct GroupClaimsRow {
    id: Option<Uuid>,
    name: String,
    selected: bool,
    claims_count: usize,
}

#[derive(Debug, Clone)]
struct ClientClaimMapView {
    ordinal: usize,
    row: ClaimMapRow,
}

#[derive(Debug, Clone)]
struct GroupClaimMapView {
    ordinal: usize,
    row: ClaimMapRow,
}

#[derive(Debug, Clone, FromRow)]
struct ClaimMapPatternRow {
    id: Uuid,
    claim_map_id: Uuid,
    pattern: String,
    is_include: bool,
    priority: i32,
}

#[derive(Debug, Clone, FromRow)]
struct AuditEventRow {
    created_at: DateTime<Utc>,
    action: String,
    resource_type: String,
    resource_id: Option<Uuid>,
    outcome: String,
    actor_sub: Option<String>,
    actor_client_id: Option<String>,
    details: Option<serde_json::Value>,
}

impl AuditEventRow {
    fn has_actor(&self) -> bool {
        self.actor_sub.is_some() || self.actor_client_id.is_some()
    }

    fn details_display(&self) -> String {
        self.details
            .as_ref()
            .and_then(|value| serde_json::to_string_pretty(value).ok())
            .unwrap_or_else(|| "-".to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminSection {
    Dashboard,
    Users,
    Groups,
    Memberships,
    Clients,
    IdentityProviders,
    Tenants,
    Claims,
    Audit,
}

impl AdminSection {
    fn all() -> [Self; 9] {
        [
            Self::Dashboard,
            Self::Users,
            Self::Groups,
            Self::Memberships,
            Self::Clients,
            Self::IdentityProviders,
            Self::Tenants,
            Self::Claims,
            Self::Audit,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Users => "Users",
            Self::Groups => "Groups",
            Self::Memberships => "Memberships",
            Self::Clients => "Clients",
            Self::IdentityProviders => "Identity providers",
            Self::Tenants => "Tenants / domains",
            Self::Claims => "Claims",
            Self::Audit => "Audit",
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Dashboard => "/admin/ui/",
            Self::Users => "/admin/ui/users",
            Self::Groups => "/admin/ui/groups",
            Self::Memberships => "/admin/ui/memberships",
            Self::Clients => "/admin/ui/clients",
            Self::IdentityProviders => "/admin/ui/identity-providers",
            Self::Tenants => "/admin/ui/tenants",
            Self::Claims => "/admin/ui/claims",
            Self::Audit => "/admin/ui/audit",
        }
    }
}

#[derive(Template)]
#[template(path = "admin/login.html")]
struct LoginTemplate<'a> {
    error: Option<&'a str>,
    next: String,
}

#[derive(Template)]
#[template(path = "admin/users.html")]
struct UsersTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    ad_link: Option<String>,
    federated_link: Option<String>,
    rows: Vec<UserRow>,
    deleted_rows: Vec<UserRow>,
    ad_modal_data: Vec<UserAdMappingModalData>,
    ad_onboarding_tokens: Vec<AdOnboardingTokenView>,
    identity_providers: Vec<IdentityProviderRow>,
    filter_q: String,
    filter_status: String,
    filter_note: String,
    letter_filters: Vec<LetterFilter>,
    current_page: u32,
    total_pages: u32,
    has_prev: bool,
    has_next: bool,
    prev_page_url: String,
    next_page_url: String,
    total_items: i64,
}

#[derive(Template)]
#[template(path = "admin/federated_onboarding_complete.html")]
struct FederatedOnboardingCompleteTemplate<'a> {
    message: &'a str,
}

#[derive(Debug, Clone)]
struct AdOnboardingTokenView {
    token_hash: String,
    username: String,
    email: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    status: String,
    status_class: String,
}

#[derive(Debug, Clone)]
struct LetterFilter {
    value: String,
    selected: bool,
}

#[derive(Template)]
#[template(path = "admin/users_import.html")]
struct UsersImportTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/groups.html")]
struct GroupsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    tree_rows: Vec<GroupTreeRow>,
    deleted_rows: Vec<GroupRow>,
}

#[derive(Template)]
#[template(path = "admin/tenants.html")]
struct TenantsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    tenants: Vec<TenantRow>,
    domains: Vec<TenantDomainRow>,
    deleted_domains: Vec<TenantDomainRow>,
}

#[derive(Template)]
#[template(path = "admin/identity_providers.html")]
struct IdentityProvidersTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<IdentityProviderRow>,
    deleted_rows: Vec<IdentityProviderRow>,
    filter_q: String,
}

#[derive(Template)]
#[template(path = "admin/memberships.html")]
struct MembershipsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    users: Vec<MembershipUserOption>,
    groups: Vec<MembershipGroupOption>,
    selected_user: Option<MembershipUserOption>,
    selected_group: Option<MembershipGroupOption>,
    selected_user_groups: Vec<UserAssignedGroupRow>,
    selected_user_patterns: Vec<UserGroupPatternRow>,
    selected_group_users: Vec<GroupAssignedUserRow>,
    available_groups: Vec<MembershipGroupOption>,
    available_users: Vec<MembershipUserOption>,
    user_filter: String,
    group_filter: String,
}

#[derive(Template)]
#[template(path = "admin/clients.html")]
struct ClientsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<ClientRow>,
    deleted_rows: Vec<ClientRow>,
    client_patterns: Vec<ClientGroupPatternRow>,
    filter_q: String,
}

#[derive(Template)]
#[template(path = "admin/claims.html")]
struct ClaimsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    client_rows: Vec<ClientClaimsRow>,
    groups: Vec<(Uuid, String)>,
    selected_client: Option<ClientClaimsRow>,
    selected_client_claim_maps: Vec<ClientClaimMapView>,
    group_rows: Vec<GroupClaimsRow>,
    clients: Vec<(Uuid, String)>,
    selected_group: Option<GroupClaimsRow>,
    selected_group_claim_maps: Vec<GroupClaimMapView>,
    deleted_claim_maps: Vec<ClaimMapRow>,
    claim_patterns: Vec<ClaimMapPatternRow>,
}

#[derive(Template)]
#[template(path = "admin/audit.html")]
struct AuditTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<AuditEventRow>,
    filter_action: String,
    filter_resource_type: String,
    filter_outcome: String,
    filter_q: String,
    filter_range: String,
}

#[derive(Clone)]
struct NavItem {
    title: &'static str,
    path: &'static str,
    active: bool,
}

#[derive(Template)]
#[template(path = "admin/ad_onboarding.html")]
struct AdOnboardingTemplate {
    message: Option<String>,
    error: Option<String>,
    token: String,
}

#[derive(Template)]
#[template(path = "admin/ad_onboarding_tokens.html")]
struct AdOnboardingTokensTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<AdOnboardingTokenRow>,
}

#[derive(Template)]
#[template(path = "admin/ad_roles.html")]
struct AdRolesTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    email: String,
    rows: Vec<ExternalRoleRow>,
}

#[derive(Template)]
#[template(path = "admin/ad_role_mappings.html")]
struct AdRoleMappingsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<ExternalRoleMappingRow>,
    groups: Vec<(Uuid, String)>,
}

#[derive(Template)]
#[template(path = "admin/dashboard.html")]
struct DashboardTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    users_total: i64,
    users_active: i64,
    users_local: i64,
    users_ad: i64,
    users_federated: i64,
    groups_total: i64,
    clients_total: i64,
    providers_total: i64,
    claim_maps_total: i64,
    managed_domains: Vec<String>,
}

pub fn router(state: WebAdminState) -> Router {
    Router::new()
        .route(
            "/ad/onboarding",
            get(ad_onboarding_page).post(ad_onboarding_submit),
        )
        .route("/federated/onboarding", get(federated_onboarding_start))
        .route(
            "/federated/onboarding/{provider}/callback",
            get(federated_onboarding_callback),
        )
        .route("/admin/ui/static/users.js", get(users_js))
        .route("/admin/ui/static/{*path}", get(admin_static_asset))
        .route("/admin/ui", get(ui_dashboard))
        .route("/admin/ui/", get(ui_dashboard))
        .route("/admin/ui/audit", get(audit_page))
        .route("/admin/ui/login", get(login_page).post(login_submit))
        .route("/admin/ui/logout", post(logout_submit))
        .route("/admin/ui/users", get(users_page))
        .route("/admin/ui/ad-onboarding", get(ad_onboarding_tokens_page))
        .route("/admin/ui/ad-roles", get(ad_roles_page))
        .route("/admin/ui/ad-role-mappings", get(ad_role_mappings_page))
        .route(
            "/admin/ui/ad-role-mappings/create",
            post(ad_role_mappings_create),
        )
        .route(
            "/admin/ui/ad-role-mappings/{id}/deactivate",
            post(ad_role_mappings_deactivate),
        )
        .route("/admin/ui/users/create", post(users_create))
        .route(
            "/admin/ui/users/import",
            get(users_import_page).post(users_import_submit),
        )
        .route("/admin/ui/users/{id}/update", post(users_update))
        .route("/admin/ui/users/{id}/mfa-reset", post(users_mfa_reset))
        .route(
            "/admin/ui/users/{id}/patterns/create",
            post(user_patterns_create),
        )
        .route(
            "/admin/ui/users/{user_id}/patterns/{pattern_id}/update",
            post(user_patterns_update),
        )
        .route(
            "/admin/ui/users/{user_id}/patterns/{pattern_id}/deactivate",
            post(user_patterns_deactivate),
        )
        .route("/admin/ui/users/{id}/deactivate", post(users_deactivate))
        .route("/admin/ui/users/{id}/restore", post(users_restore))
        .route(
            "/admin/ui/ad-onboarding/delete",
            post(ad_onboarding_tokens_bulk_delete),
        )
        .route(
            "/admin/ui/users/{id}/ad-mappings/apply",
            post(users_ad_mappings_apply),
        )
        .route(
            "/admin/ui/users/{id}/ad-onboarding-link",
            post(users_ad_onboarding_link),
        )
        .route(
            "/admin/ui/users/{id}/federated-invitation-link",
            post(users_federated_invitation_link),
        )
        .route(
            "/admin/ui/users/{id}/federated-approve",
            post(users_federated_approve),
        )
        .route(
            "/admin/ui/users/{id}/federated-unlink",
            post(users_federated_unlink),
        )
        .route("/admin/ui/groups", get(groups_page))
        .route("/admin/ui/groups/create", post(groups_create))
        .route("/admin/ui/groups/{id}/update", post(groups_update))
        .route("/admin/ui/groups/{id}/reparent", post(groups_reparent))
        .route("/admin/ui/groups/{id}/deactivate", post(groups_deactivate))
        .route("/admin/ui/groups/{id}/restore", post(groups_restore))
        .route("/admin/ui/tenants", get(tenants_page))
        .route("/admin/ui/tenants/{id}/update", post(tenants_update))
        .route(
            "/admin/ui/tenant-domains/create",
            post(tenant_domains_create),
        )
        .route(
            "/admin/ui/tenant-domains/{id}/update",
            post(tenant_domains_update),
        )
        .route(
            "/admin/ui/tenant-domains/{id}/deactivate",
            post(tenant_domains_deactivate),
        )
        .route(
            "/admin/ui/tenant-domains/{id}/restore",
            post(tenant_domains_restore),
        )
        .route("/admin/ui/identity-providers", get(identity_providers_page))
        .route(
            "/admin/ui/identity-providers/create",
            post(identity_providers_create),
        )
        .route(
            "/admin/ui/identity-providers/{id}/update",
            post(identity_providers_update),
        )
        .route(
            "/admin/ui/identity-providers/{id}/deactivate",
            post(identity_providers_deactivate),
        )
        .route(
            "/admin/ui/identity-providers/{id}/restore",
            post(identity_providers_restore),
        )
        .route("/admin/ui/memberships", get(memberships_page))
        .route(
            "/admin/ui/memberships/users/{user_id}/groups/add",
            post(memberships_add_groups_to_user),
        )
        .route(
            "/admin/ui/memberships/users/{user_id}/groups/{group_id}/remove",
            post(memberships_remove_group_from_user),
        )
        .route(
            "/admin/ui/memberships/users/{user_id}/groups/remove",
            post(memberships_remove_groups_from_user),
        )
        .route(
            "/admin/ui/memberships/groups/{group_id}/users/add",
            post(memberships_add_users_to_group),
        )
        .route(
            "/admin/ui/memberships/groups/{group_id}/users/{user_id}/remove",
            post(memberships_remove_user_from_group),
        )
        .route(
            "/admin/ui/memberships/groups/{group_id}/users/remove",
            post(memberships_remove_users_from_group),
        )
        .route("/admin/ui/user-groups", get(user_groups_redirect))
        .route("/admin/ui/group-users", get(group_users_redirect))
        .route("/admin/ui/clients", get(clients_page))
        .route("/admin/ui/clients/create", post(clients_create))
        .route("/admin/ui/clients/{id}/update", post(clients_update))
        .route(
            "/admin/ui/clients/{id}/patterns/create",
            post(client_patterns_create),
        )
        .route(
            "/admin/ui/clients/{client_id}/patterns/{pattern_id}/update",
            post(client_patterns_update),
        )
        .route(
            "/admin/ui/clients/{client_id}/patterns/{pattern_id}/deactivate",
            post(client_patterns_deactivate),
        )
        .route(
            "/admin/ui/clients/{id}/deactivate",
            post(clients_deactivate),
        )
        .route("/admin/ui/clients/{id}/restore", post(clients_restore))
        .route("/admin/ui/claims", get(claims_page))
        .route("/admin/ui/client-claims", get(client_claims_redirect))
        .route("/admin/ui/client-claims/create", post(client_claims_create))
        .route(
            "/admin/ui/client-claims/{id}/update",
            post(claim_maps_update),
        )
        .route(
            "/admin/ui/client-claims/{id}/deactivate",
            post(claim_maps_deactivate),
        )
        .route(
            "/admin/ui/claim-maps/{id}/patterns/create",
            post(claim_patterns_create),
        )
        .route(
            "/admin/ui/claim-maps/{claim_map_id}/patterns/{pattern_id}/update",
            post(claim_patterns_update),
        )
        .route(
            "/admin/ui/claim-maps/{claim_map_id}/patterns/{pattern_id}/deactivate",
            post(claim_patterns_deactivate),
        )
        .route(
            "/admin/ui/claim-maps/{id}/restore",
            post(claim_maps_restore),
        )
        .route("/admin/ui/group-claims", get(group_claims_redirect))
        .route(
            "/admin/ui/group-claims/{id}/update",
            post(claim_maps_update),
        )
        .route(
            "/admin/ui/group-claims/{id}/deactivate",
            post(claim_maps_deactivate),
        )
        .with_state(state)
}

async fn users_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        USERS_PAGE_JS,
    )
}

async fn admin_static_asset(Path(path): Path<String>) -> Response {
    embedded_asset_response(&path)
}

const USERS_PAGE_JS: &str = r#"
document.addEventListener('DOMContentLoaded', function() {
  const filterForm = document.getElementById('users-filter-form');
  const FILTER_COOKIE = 'sidm_users_filters';

  function setCookie(name, value, days) {
    const expires = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toUTCString();
    document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax`;
  }

  function getCookie(name) {
    const raw = document.cookie
      .split('; ')
      .find((row) => row.startsWith(`${name}=`));
    if (!raw) return null;
    return decodeURIComponent(raw.substring(name.length + 1));
  }

  function clearCookie(name) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; SameSite=Lax`;
  }

  function updateLettersHidden() {
    if (!filterForm) return;
    const selected = Array.from(filterForm.querySelectorAll('.letter-filter:checked'))
      .map(el => el.value)
      .join(',');
    const hidden = document.getElementById('letters-hidden');
    if (hidden) hidden.value = selected;
  }
  if (filterForm) {
    const qInput = filterForm.querySelector('input[name="q"]');
    const statusSelect = filterForm.querySelector('select[name="status"]');
    const noteInput = filterForm.querySelector('input[name="note"]');
    let lastFocusName = null;
    let lastFocusPos = null;
    let filterRequestSeq = 0;
    let resultsInteractionSeq = 0;

    document.addEventListener('pointerdown', (e) => {
      if (e.target instanceof Element && e.target.closest('#users-results')) {
        resultsInteractionSeq += 1;
      }
    }, true);

    function getSelectedLetters() {
      return Array.from(filterForm.querySelectorAll('.letter-filter:checked')).map(el => el.value);
    }

    function persistFilters() {
      const payload = {
        q: (qInput?.value || '').trim(),
        status: statusSelect?.value || 'all',
        note: (noteInput?.value || '').trim(),
        letters: getSelectedLetters()
      };
      setCookie(FILTER_COOKIE, JSON.stringify(payload), 14);
    }

    function applyPersistedFilters() {
      const raw = getCookie(FILTER_COOKIE);
      if (!raw) return false;
      let saved = null;
      try {
        saved = JSON.parse(raw);
      } catch (_) {
        return false;
      }
      if (!saved || typeof saved !== 'object') return false;

      if (qInput) qInput.value = saved.q || '';
      if (statusSelect) statusSelect.value = saved.status || 'all';
      if (noteInput) noteInput.value = saved.note || '';

      const selected = new Set(Array.isArray(saved.letters) ? saved.letters : []);
      filterForm.querySelectorAll('.letter-filter').forEach((el) => {
        el.checked = selected.has(el.value);
      });
      updateLettersHidden();

      return Boolean(
        (saved.q && saved.q.trim().length > 0) ||
        (saved.note && saved.note.trim().length > 0) ||
        (saved.status && saved.status !== 'all') ||
        (Array.isArray(saved.letters) && saved.letters.length > 0)
      );
    }

    const params = new URLSearchParams(window.location.search);
    const hasQueryState =
      params.has('q') || params.has('status') || params.has('note') || params.has('letters');
    const hasUiMessageState =
      params.has('message') || params.has('error') || params.has('ad_link') || params.has('federated_link');

    function captureFocusState(el) {
      if (!el || !el.name) return;
      lastFocusName = el.name;
      if (typeof el.selectionStart === 'number') {
        lastFocusPos = el.selectionStart;
      } else {
        lastFocusPos = null;
      }
    }

    [qInput, noteInput, statusSelect].forEach((el) => {
      if (!el) return;
      el.addEventListener('focus', () => captureFocusState(el));
      el.addEventListener('click', () => captureFocusState(el));
      el.addEventListener('input', () => captureFocusState(el));
      el.addEventListener('keyup', () => captureFocusState(el));
      el.addEventListener('change', () => captureFocusState(el));
    });

    async function navigateWithFilters(focusName) {
      updateLettersHidden();
      persistFilters();
      const requestSeq = ++filterRequestSeq;
      const interactionSeq = resultsInteractionSeq;
      const p = new URLSearchParams();
      p.set('q', (qInput?.value || '').trim());
      p.set('status', statusSelect?.value || 'all');
      p.set('note', (noteInput?.value || '').trim());
      p.set('letters', document.getElementById('letters-hidden')?.value || '');
      if (focusName) p.set('_focus', focusName);
      if (typeof lastFocusPos === 'number') p.set('_cursor', String(lastFocusPos));
      const url = `/admin/ui/users?${p.toString()}`;
      const resultsRoot = document.getElementById('users-results');
      if (!resultsRoot) {
        window.location.assign(url);
        return;
      }
      try {
        resultsRoot.style.opacity = '0.55';
        const response = await fetch(url, {
          headers: {
            'X-Requested-With': 'XMLHttpRequest'
          }
        });
        if (!response.ok) {
          window.location.assign(url);
          return;
        }
        const html = await response.text();
        const parsed = new DOMParser().parseFromString(html, 'text/html');
        const nextResults = parsed.getElementById('users-results');
        if (!nextResults) {
          window.location.assign(url);
          return;
        }
        if (requestSeq !== filterRequestSeq || interactionSeq !== resultsInteractionSeq) {
          return;
        }
        resultsRoot.replaceWith(nextResults);
        history.replaceState({}, '', url);
        initAdMapForms();
        initAdTokenControls();
        applyFocusFromUrlParams(new URL(url, window.location.origin).searchParams);
      } catch (_) {
        window.location.assign(url);
      } finally {
        const newRoot = document.getElementById('users-results');
        if (newRoot) newRoot.style.opacity = '';
      }
    }

    let shouldAutoApplyPersisted = false;
    if (!hasQueryState && !hasUiMessageState) {
      shouldAutoApplyPersisted = applyPersistedFilters();
    }

    let debounceTimer = null;
    filterForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const active = document.activeElement;
      if (active && active.name) captureFocusState(active);
      navigateWithFilters(lastFocusName);
    });
    const liveInputs = filterForm.querySelectorAll('input[name=\"q\"], input[name=\"note\"], select[name=\"status\"]');
    liveInputs.forEach((el) => {
      el.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          void navigateWithFilters(el.name || lastFocusName);
        }, 300);
      });
      el.addEventListener('change', () => {
        clearTimeout(debounceTimer);
        void navigateWithFilters(el.name || lastFocusName);
      });
    });
    filterForm.querySelectorAll('.letter-filter').forEach((el) => {
      el.addEventListener('change', () => {
        clearTimeout(debounceTimer);
        void navigateWithFilters(lastFocusName || 'q');
      });
    });

    const resetBtn = document.getElementById('users-filter-reset');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        clearCookie(FILTER_COOKIE);
        window.location.href = '/admin/ui/users';
      });
    }

    function applyFocusFromUrlParams(urlParams) {
      const focusName = urlParams.get('_focus');
      const focusPosRaw = urlParams.get('_cursor');
      if (!focusName) return;
      const target = filterForm.querySelector(`[name="${focusName}"]`);
      if (target) {
        setTimeout(() => {
          target.focus();
          if (target.setSelectionRange && typeof target.value === 'string') {
            const parsed = Number.parseInt(focusPosRaw || '', 10);
            const pos = Number.isFinite(parsed) ? Math.min(parsed, target.value.length) : target.value.length;
            target.setSelectionRange(pos, pos);
          }
        }, 0);
      }
      urlParams.delete('_focus');
      urlParams.delete('_cursor');
      const next = urlParams.toString();
      history.replaceState({}, '', next ? `/admin/ui/users?${next}` : '/admin/ui/users');
    }
    applyFocusFromUrlParams(params);

    if (shouldAutoApplyPersisted) {
      setTimeout(() => { void navigateWithFilters(null); }, 0);
    }
  }

  function randomPassword(length) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=';
    const bytes = new Uint32Array(length);
    window.crypto.getRandomValues(bytes);
    let out = '';
    for (let i = 0; i < length; i++) out += alphabet[bytes[i] % alphabet.length];
    return out;
  }

  document.addEventListener('click', async (e) => {
    const gen = e.target.closest('.user-password-generate');
    if (gen) {
      const targetId = gen.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input) return;
      input.value = randomPassword(20);
      input.type = 'text';
      return;
    }
    const copy = e.target.closest('.user-password-copy');
    if (copy) {
      const targetId = copy.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input || !input.value) return;
      try {
        await navigator.clipboard.writeText(input.value);
      } catch (_) {
        input.select();
        document.execCommand('copy');
      }
      return;
    }
    const linkCopy = e.target.closest('.copy-link');
    if (linkCopy) {
      const value = linkCopy.getAttribute('data-copy-link');
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
      } catch (_) {
        const textarea = document.createElement('textarea');
        textarea.value = value;
        textarea.setAttribute('readonly', 'readonly');
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        textarea.remove();
      }
    }
  });

  function applyFilter(inputEl, itemSelector) {
    const root = inputEl.closest('.modal-content');
    if (!root) return;
    const terms = inputEl.value
      .toLowerCase()
      .split(/\s+/)
      .map(t => t.trim())
      .filter(Boolean);
    root.querySelectorAll(itemSelector).forEach(item => {
      const text = item.textContent.toLowerCase();
      const matches = terms.every(term => text.includes(term));
      item.style.display = matches ? '' : 'none';
    });
  }

  document.addEventListener('input', (e) => {
    if (!(e.target instanceof Element)) return;
    const left = e.target.closest('.ad-filter-left');
    if (left) {
      applyFilter(left, '.ad-left-item');
      return;
    }
    const right = e.target.closest('.ad-filter-right');
    if (right) {
      applyFilter(right, '.ad-right-item');
      return;
    }
    const draft = e.target.closest('.ad-filter-draft');
    if (draft) {
      applyFilter(draft, '.ad-draft-item');
    }
  });

  function mappingKey(r, g) {
    return `${r}__${g}`;
  }

  function initAdMapForms() {
    document.querySelectorAll('.ad-map-form').forEach(form => {
      if (form.dataset.initialized === '1') return;
      form.dataset.initialized = '1';
      const draft = new Map();
      const tbody = form.querySelector('.ad-draft-table tbody');
      const jsonInput = form.querySelector('.ad-mappings-json');
      const addBtn = form.querySelector('.ad-add-btn');
      const removeSelectedBtn = form.querySelector('.ad-remove-selected');
      const selectAll = form.querySelector('.ad-draft-select-all');
      if (!tbody || !jsonInput || !addBtn) return;

      let existingRaw = form.dataset.existing || '[]';
      let existingItems = [];
      try {
        existingItems = JSON.parse(existingRaw);
      } catch (_) {
        existingItems = [];
      }
      existingItems.forEach((item) => {
        if (!item || !item.external_role || !item.group_id) return;
        const key = mappingKey(item.external_role, String(item.group_id));
        draft.set(key, {
          mapping_id: item.id ? String(item.id) : null,
          external_role: String(item.external_role),
          group_id: String(item.group_id),
          group_name: String(item.group_name || item.group_id),
          priority: Number(item.priority) || 100,
          existing: true,
          action: 'keep'
        });
      });

      function collectPayload() {
        const out = [];
        for (const item of draft.values()) {
          if (item.action === 'add') {
            out.push({
              mapping_id: null,
              external_role: item.external_role,
              group_id: item.group_id,
              priority: Number(item.priority) || 100,
              mode: 'add'
            });
          } else if (item.action === 'deactivate' && item.mapping_id) {
            out.push({
              mapping_id: item.mapping_id,
              external_role: item.external_role,
              group_id: item.group_id,
              priority: Number(item.priority) || 100,
              mode: 'deactivate'
            });
          }
        }
        return out;
      }

      function refreshDraftTable() {
        tbody.innerHTML = '';
        for (const [key, item] of draft.entries()) {
          const isNew = item.action === 'add';
          const isMarkedForRemoval = item.action === 'deactivate';
          const statusBadge = isMarkedForRemoval
            ? '<span class="badge bg-red-lt">remove</span>'
            : (item.existing ? '<span class="badge bg-secondary-lt">existing</span>' : '<span class="badge bg-green-lt">new</span>');
          const tr = document.createElement('tr');
          tr.className = `ad-draft-item ${isNew ? 'bg-success-lt' : ''} ${isMarkedForRemoval ? 'bg-danger-lt' : ''}`;
          tr.innerHTML = `
            <td><input type="checkbox" class="form-check-input ad-draft-check" data-key="${key}"></td>
            <td>${statusBadge}</td>
            <td><code class="small">${item.external_role}</code></td>
            <td>${item.group_name}</td>
            <td><input type="number" class="form-control form-control-sm ad-priority" data-key="${key}" value="${item.priority}" style="max-width:100px;" ${isMarkedForRemoval ? 'disabled' : ''}></td>
            <td><button type="button" class="btn btn-sm btn-outline-danger ad-remove" data-key="${key}">${item.existing ? 'Toggle remove' : 'Remove'}</button></td>
          `;
          tbody.appendChild(tr);
        }
        jsonInput.value = JSON.stringify(collectPayload());
      }

      addBtn.addEventListener('click', () => {
        const selectedRoles = Array.from(form.querySelectorAll('.ad-left-check:checked'));
        const selectedGroups = Array.from(form.querySelectorAll('.ad-right-check:checked'));
        selectedRoles.forEach(r => {
          selectedGroups.forEach(g => {
            const groupLabel = g.closest('label')?.textContent?.trim() || g.value;
            const k = mappingKey(r.value, g.value);
            if (!draft.has(k)) {
              draft.set(k, {
                mapping_id: null,
                external_role: r.value,
                group_id: g.value,
                group_name: groupLabel,
                priority: 100,
                existing: false,
                action: 'add'
              });
            } else {
              const current = draft.get(k);
              if (current.existing && current.action === 'deactivate') {
                current.action = 'keep';
                draft.set(k, current);
              }
            }
          });
        });
        refreshDraftTable();
      });

      tbody.addEventListener('click', (e) => {
        const btn = e.target.closest('.ad-remove');
        if (!btn) return;
        const key = btn.getAttribute('data-key');
        if (!draft.has(key)) return;
        const item = draft.get(key);
        if (item.existing) {
          item.action = item.action === 'deactivate' ? 'keep' : 'deactivate';
          draft.set(key, item);
        } else {
          draft.delete(key);
        }
        refreshDraftTable();
      });

      if (removeSelectedBtn) {
        removeSelectedBtn.addEventListener('click', () => {
          const selected = Array.from(form.querySelectorAll('.ad-draft-check:checked'));
          selected.forEach((cb) => {
            const key = cb.getAttribute('data-key');
            if (!draft.has(key)) return;
            const item = draft.get(key);
            if (item.existing) {
              item.action = 'deactivate';
              draft.set(key, item);
            } else {
              draft.delete(key);
            }
          });
          refreshDraftTable();
        });
      }

      if (selectAll) {
        selectAll.addEventListener('change', () => {
          const checked = Boolean(selectAll.checked);
          form.querySelectorAll('.ad-draft-check').forEach((cb) => {
            cb.checked = checked;
          });
        });
      }

      tbody.addEventListener('input', (e) => {
        const inp = e.target.closest('.ad-priority');
        if (!inp) return;
        const key = inp.getAttribute('data-key');
        if (!draft.has(key)) return;
        const item = draft.get(key);
        item.priority = Number(inp.value) || 100;
        draft.set(key, item);
        jsonInput.value = JSON.stringify(collectPayload());
      });

      form.addEventListener('submit', (e) => {
        const payload = collectPayload();
        if (payload.length === 0) {
          e.preventDefault();
          alert('No mapping changes selected.');
          return;
        }
        jsonInput.value = JSON.stringify(payload);
      });

      refreshDraftTable();
    });
  }
  initAdMapForms();

  function initAdTokenControls() {
    const tokenStatusFilter = document.getElementById('ad-token-status-filter');
    const tokenRows = Array.from(document.querySelectorAll('.ad-token-row'));
    if (tokenStatusFilter && tokenStatusFilter.dataset.initialized !== '1') {
      tokenStatusFilter.dataset.initialized = '1';
      tokenStatusFilter.addEventListener('change', () => {
        const status = tokenStatusFilter.value;
        tokenRows.forEach((row) => {
          const rowStatus = row.getAttribute('data-status') || 'all';
          row.style.display = status === 'all' || status === rowStatus ? '' : 'none';
        });
      });
    }

    const tokenSelectAll = document.getElementById('ad-token-select-all');
    if (tokenSelectAll && tokenSelectAll.dataset.initialized !== '1') {
      tokenSelectAll.dataset.initialized = '1';
      tokenSelectAll.addEventListener('change', () => {
        document.querySelectorAll('.ad-token-check').forEach((el) => {
          const row = el.closest('tr');
          if (!row || row.style.display === 'none') return;
          el.checked = tokenSelectAll.checked;
        });
      });
    }

    const tokenDeleteForm = document.querySelector('form[action=\"/admin/ui/ad-onboarding/delete\"]');
    const tokenHashesCsv = document.getElementById('ad-token-hashes-csv');
    if (tokenDeleteForm && tokenHashesCsv && tokenDeleteForm.dataset.initialized !== '1') {
      tokenDeleteForm.dataset.initialized = '1';
      tokenDeleteForm.addEventListener('submit', (e) => {
        const selected = Array.from(document.querySelectorAll('.ad-token-check:checked'))
          .map(el => el.value)
          .filter(Boolean);
        tokenHashesCsv.value = selected.join(',');
        if (selected.length === 0) {
          e.preventDefault();
          alert('No onboarding token selected.');
        }
      });
    }
  }
  initAdTokenControls();
});
"#;

fn parse_checkbox(v: &Option<String>) -> bool {
    v.as_deref()
        .is_some_and(|x| x == "on" || x == "true" || x == "1")
}

fn parse_google_signin_datetime(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let formats = ["%Y/%m/%d %H:%M:%S", "%Y/%m/%d %-H:%M:%S"];
    for fmt in formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
        }
    }
    None
}

fn normalize_opt(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

fn normalize_opt_form(raw: Option<String>) -> Option<String> {
    raw.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn looks_like_email(value: &str) -> bool {
    let value = value.trim();
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

fn looks_like_e164(value: &str) -> bool {
    let value = value.trim();
    value.starts_with('+')
        && value.len() >= 8
        && value.len() <= 16
        && value[1..].chars().all(|c| c.is_ascii_digit())
}

fn username_from_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn random_import_password() -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

fn normalize_auth_mode(raw: Option<&str>) -> String {
    match raw.unwrap_or("local").trim().to_lowercase().as_str() {
        "federated" => "federated".to_string(),
        "ad" | "mixed" => "ad".to_string(),
        _ => "local".to_string(),
    }
}

fn parse_google_users_csv(bytes: &[u8]) -> Result<Vec<ImportedCsvUser>, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(bytes);
    let headers = rdr
        .headers()
        .map_err(|e| format!("Failed to read CSV header: {e}"))?
        .clone();

    let idx = |name: &str| {
        headers
            .iter()
            .position(|h| h.trim_start_matches('\u{feff}').trim() == name)
    };
    let email_idx = idx("Email Address [Required]")
        .ok_or_else(|| "CSV missing 'Email Address [Required]' column".to_string())?;
    let first_idx = idx("First Name [Required]");
    let last_idx = idx("Last Name [Required]");
    let status_idx = idx("Status [READ ONLY]");
    let last_sign_in_idx = idx("Last Sign In [READ ONLY]");
    let recovery_email_idx = idx("Recovery Email");
    let mobile_phone_idx = idx("Mobile Phone");
    let recovery_phone_idx = idx("Recovery Phone [MUST BE IN THE E.164 FORMAT]");

    let mut out = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| format!("Invalid CSV row: {e}"))?;
        let email = rec.get(email_idx).unwrap_or_default().trim().to_lowercase();
        if email.is_empty() {
            continue;
        }
        let is_active = rec
            .get(status_idx.unwrap_or(usize::MAX))
            .map(|s| s.trim().eq_ignore_ascii_case("active"))
            .unwrap_or(true);

        let mobile_phone = normalize_opt(rec.get(mobile_phone_idx.unwrap_or(usize::MAX)));
        let recovery_phone = normalize_opt(rec.get(recovery_phone_idx.unwrap_or(usize::MAX)));
        let phone = mobile_phone.or(recovery_phone);
        let last_sign_in_at = rec
            .get(last_sign_in_idx.unwrap_or(usize::MAX))
            .and_then(parse_google_signin_datetime);

        out.push(ImportedCsvUser {
            first_name: normalize_opt(rec.get(first_idx.unwrap_or(usize::MAX))),
            last_name: normalize_opt(rec.get(last_idx.unwrap_or(usize::MAX))),
            email,
            recovery_email: normalize_opt(rec.get(recovery_email_idx.unwrap_or(usize::MAX))),
            phone,
            last_sign_in_at,
            is_active,
        });
    }
    Ok(out)
}

fn split_csv(v: &str) -> Vec<String> {
    v.split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect()
}

fn split_claim_values(v: &str) -> Vec<String> {
    v.split([',', '\n'])
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect()
}

fn claim_value_columns(kind: &str, raw_value: &str) -> (String, Option<String>, Option<String>) {
    if kind == "array" {
        let values = split_claim_values(raw_value);
        let json = serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string());
        ("array".to_string(), None, Some(json))
    } else {
        (
            "single".to_string(),
            Some(raw_value.trim().to_string()),
            None,
        )
    }
}

fn selected_grant_types(form_values: &[String], fallback_csv: Option<&str>) -> Vec<String> {
    if !form_values.is_empty() {
        return form_values.to_vec();
    }
    fallback_csv.map(split_csv).unwrap_or_default()
}

fn selected_scope_string(form_values: &[String], fallback_scope: Option<&str>) -> String {
    if !form_values.is_empty() {
        return form_values.join(" ");
    }
    fallback_scope
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn selected_grant_types_from_flags(
    authorization_code: &Option<String>,
    refresh_token: &Option<String>,
    client_credentials: &Option<String>,
    device_code: &Option<String>,
) -> Vec<String> {
    let mut v = Vec::new();
    if parse_checkbox(authorization_code) {
        v.push("authorization_code".to_string());
    }
    if parse_checkbox(refresh_token) {
        v.push("refresh_token".to_string());
    }
    if parse_checkbox(client_credentials) {
        v.push("client_credentials".to_string());
    }
    if parse_checkbox(device_code) {
        v.push("urn:ietf:params:oauth:grant-type:device_code".to_string());
    }
    v
}

fn selected_scopes_from_flags(
    openid: &Option<String>,
    profile: &Option<String>,
    email: &Option<String>,
    groups: &Option<String>,
    offline_access: &Option<String>,
) -> Vec<String> {
    let mut v = Vec::new();
    if parse_checkbox(openid) {
        v.push("openid".to_string());
    }
    if parse_checkbox(profile) {
        v.push("profile".to_string());
    }
    if parse_checkbox(email) {
        v.push("email".to_string());
    }
    if parse_checkbox(groups) {
        v.push("groups".to_string());
    }
    if parse_checkbox(offline_access) {
        v.push("offline_access".to_string());
    }
    v
}

fn normalize_groups_claim_mode(raw: Option<&str>) -> String {
    match raw.unwrap_or("effective").trim().to_lowercase().as_str() {
        "direct" => "direct".to_string(),
        "none" => "none".to_string(),
        _ => "effective".to_string(),
    }
}

fn pattern_mode_to_bool(mode: &str) -> bool {
    !mode.trim().eq_ignore_ascii_case("exclude")
}

fn pattern_priority(value: Option<i32>) -> i32 {
    value.unwrap_or(100)
}

fn selected_oidc_provider_scopes(
    openid: &Option<String>,
    profile: &Option<String>,
    email: &Option<String>,
) -> Vec<String> {
    let mut scopes = Vec::new();
    if parse_checkbox(openid) {
        scopes.push("openid".to_string());
    }
    if parse_checkbox(profile) {
        scopes.push("profile".to_string());
    }
    if parse_checkbox(email) {
        scopes.push("email".to_string());
    }
    if scopes.is_empty() {
        vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]
    } else if scopes.iter().any(|s| s == "openid") {
        scopes
    } else {
        let mut with_openid = vec!["openid".to_string()];
        with_openid.extend(scopes);
        with_openid
    }
}

fn csv_to_vec(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

fn normalize_provider_type(raw: &str) -> String {
    match raw.trim().to_lowercase().as_str() {
        "ad_ldap" => "ad_ldap".to_string(),
        "google" => "google".to_string(),
        "oidc" => "oidc".to_string(),
        _ => "oidc".to_string(),
    }
}

fn deserialize_string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrSeqVisitor;

    impl<'de> Visitor<'de> for StringOrSeqVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or a sequence of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(item) = seq.next_element::<String>()? {
                values.push(item);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(StringOrSeqVisitor)
}

fn deserialize_opt_string_or_seq<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = deserialize_string_or_seq(deserializer)?;
    if v.is_empty() { Ok(None) } else { Ok(Some(v)) }
}

fn nav_items(active: AdminSection) -> Vec<NavItem> {
    AdminSection::all()
        .into_iter()
        .map(|s| NavItem {
            title: s.title(),
            path: s.path(),
            active: s == active,
        })
        .collect()
}

fn redirect_with(path: &str, key: &str, value: &str) -> Redirect {
    let encoded = urlencoding::encode(value);
    let sep = if path.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{path}{sep}{key}={encoded}"))
}

fn default_tenant_id() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("valid default tenant UUID")
}

fn parse_csv_list(input: Option<&str>) -> Vec<String> {
    input
        .unwrap_or_default()
        .split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect()
}

fn parse_uuid_csv(input: Option<&str>) -> Vec<Uuid> {
    parse_csv_list(input)
        .into_iter()
        .filter_map(|id| Uuid::parse_str(&id).ok())
        .collect()
}

fn parse_parent_group_id(input: Option<&str>) -> Result<Option<Uuid>, String> {
    match input.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) if v.eq_ignore_ascii_case("root") => Ok(None),
        Some(v) => Uuid::parse_str(v)
            .map(Some)
            .map_err(|_| "Invalid parent_group_id".to_string()),
        None => Ok(None),
    }
}

fn normalize_domain(input: &str) -> Result<String, String> {
    let domain = input
        .trim()
        .trim_start_matches('@')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if domain.is_empty() {
        return Err("Domain is required".to_string());
    }
    if domain.contains("://") || domain.contains('/') || domain.contains('\\') {
        return Err("Domain must be a bare DNS name, for example datalite.cz".to_string());
    }
    if !domain.contains('.') {
        return Err("Domain must contain at least one dot".to_string());
    }
    if domain
        .split('.')
        .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
    {
        return Err("Domain contains an invalid DNS label".to_string());
    }
    if !domain
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.')
    {
        return Err("Domain can contain only letters, digits, hyphen and dot".to_string());
    }

    Ok(domain)
}

async fn would_create_group_cycle(
    db_pool: &DbPool,
    parent_id: Uuid,
    child_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![child_id];

    while let Some(current) = stack.pop() {
        if current == parent_id {
            return Ok(true);
        }
        if !visited.insert(current) {
            continue;
        }
        let children = sqlx::query_scalar::<_, Uuid>(
            "SELECT child_group_id FROM group_groups WHERE parent_group_id = $1",
        )
        .bind(current)
        .fetch_all(db_pool)
        .await?;
        stack.extend(children);
    }

    Ok(false)
}

fn build_group_tree_rows(rows: &[GroupRow], relations: &[(Uuid, Uuid)]) -> Vec<GroupTreeRow> {
    let mut by_id: HashMap<Uuid, &GroupRow> = HashMap::new();
    let mut children: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    let mut parent_of: HashMap<Uuid, Uuid> = HashMap::new();

    for row in rows {
        by_id.insert(row.id, row);
    }
    for (parent, child) in relations {
        children.entry(*parent).or_default().push(*child);
        parent_of.insert(*child, *parent);
    }
    for ids in children.values_mut() {
        ids.sort_by_key(|id| by_id.get(id).map(|r| r.name.clone()).unwrap_or_default());
    }

    let mut roots = rows
        .iter()
        .filter(|r| !parent_of.contains_key(&r.id))
        .map(|r| r.id)
        .collect::<Vec<_>>();
    roots.sort_by_key(|id| by_id.get(id).map(|r| r.name.clone()).unwrap_or_default());

    let mut out = Vec::new();
    let mut visited = std::collections::HashSet::new();

    fn walk(
        current: Uuid,
        depth: usize,
        by_id: &HashMap<Uuid, &GroupRow>,
        children: &HashMap<Uuid, Vec<Uuid>>,
        parent_of: &HashMap<Uuid, Uuid>,
        visited: &mut std::collections::HashSet<Uuid>,
        out: &mut Vec<GroupTreeRow>,
    ) {
        if !visited.insert(current) {
            return;
        }
        let Some(row) = by_id.get(&current) else {
            return;
        };
        out.push(GroupTreeRow {
            id: row.id,
            name: row.name.clone(),
            description: row.description.clone(),
            is_virtual: row.is_virtual,
            depth,
            parent_id: parent_of.get(&current).copied(),
        });
        if let Some(kids) = children.get(&current) {
            for child in kids {
                walk(*child, depth + 1, by_id, children, parent_of, visited, out);
            }
        }
    }

    for root in roots {
        walk(
            root,
            0,
            &by_id,
            &children,
            &parent_of,
            &mut visited,
            &mut out,
        );
    }

    for row in rows {
        if !visited.contains(&row.id) {
            walk(
                row.id,
                0,
                &by_id,
                &children,
                &parent_of,
                &mut visited,
                &mut out,
            );
        }
    }

    out
}

fn users_return_path_from_referer(headers: &HeaderMap) -> String {
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let raw_path = if referer.starts_with("http://") || referer.starts_with("https://") {
        match url::Url::parse(referer) {
            Ok(u) => {
                let mut p = u.path().to_string();
                if let Some(q) = u.query() {
                    p.push('?');
                    p.push_str(q);
                }
                p
            }
            Err(_) => "/admin/ui/users".to_string(),
        }
    } else if referer.starts_with('/') {
        referer.to_string()
    } else {
        "/admin/ui/users".to_string()
    };

    if !raw_path.starts_with("/admin/ui/users") {
        return "/admin/ui/users".to_string();
    }

    if let Some((path, query)) = raw_path.split_once('?') {
        let mut kept = Vec::new();
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = k.as_ref();
            if matches!(key, "q" | "status" | "note" | "letters" | "page") {
                kept.push((k.into_owned(), v.into_owned()));
            }
        }
        if kept.is_empty() {
            path.to_string()
        } else {
            let qs = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(kept.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .finish();
            format!("{path}?{qs}")
        }
    } else {
        raw_path
    }
}

fn user_patterns_return_path_from_referer(headers: &HeaderMap, user_id: Uuid) -> String {
    let membership_fallback = format!("/admin/ui/memberships?user_id={user_id}#by-user");
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if referer.contains("/admin/ui/memberships") {
        memberships_return_path_from_referer(headers, &membership_fallback)
    } else {
        users_return_path_from_referer(headers)
    }
}

fn public_origin_from_headers(headers: &HeaderMap) -> String {
    if let Some(origin) = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Url::parse(v).ok())
        .and_then(|url| {
            let host = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
                None => format!("{}://{}", url.scheme(), host),
            })
        })
    {
        return origin;
    }

    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let host = forwarded_host.or_else(|| headers.get(header::HOST).and_then(|v| v.to_str().ok()));

    if let Some(host) = host {
        let proto = forwarded_proto.unwrap_or("http");
        return format!("{proto}://{host}");
    }

    std::env::var("JWT_ISSUER")
        .unwrap_or_else(|_| "http://localhost:8080".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn public_url_from_headers(headers: &HeaderMap, path_and_query: &str) -> String {
    format!("{}{}", public_origin_from_headers(headers), path_and_query)
}

fn memberships_return_path_from_referer(headers: &HeaderMap, fallback: &str) -> String {
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let raw_path = if referer.starts_with("http://") || referer.starts_with("https://") {
        match url::Url::parse(referer) {
            Ok(u) => {
                let mut p = u.path().to_string();
                if let Some(q) = u.query() {
                    p.push('?');
                    p.push_str(q);
                }
                p
            }
            Err(_) => fallback.to_string(),
        }
    } else if referer.starts_with('/') {
        referer.to_string()
    } else {
        fallback.to_string()
    };

    if !raw_path.starts_with("/admin/ui/memberships") {
        return fallback.to_string();
    }

    if let Some((path, query)) = raw_path.split_once('?') {
        let mut kept = Vec::new();
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = k.as_ref();
            if matches!(key, "user_id" | "group_id" | "user_filter" | "group_filter") {
                kept.push((k.into_owned(), v.into_owned()));
            }
        }
        if kept.is_empty() {
            path.to_string()
        } else {
            let qs = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(kept.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .finish();
            format!("{path}?{qs}")
        }
    } else {
        raw_path
    }
}

fn q_return_path_from_referer(headers: &HeaderMap, prefix: &str, fallback: &str) -> String {
    scoped_return_path_from_referer(headers, prefix, fallback, &["q"])
}

fn scoped_return_path_from_referer(
    headers: &HeaderMap,
    prefix: &str,
    fallback: &str,
    kept_keys: &[&str],
) -> String {
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let raw_path = if referer.starts_with("http://") || referer.starts_with("https://") {
        match url::Url::parse(referer) {
            Ok(u) => {
                let mut p = u.path().to_string();
                if let Some(q) = u.query() {
                    p.push('?');
                    p.push_str(q);
                }
                p
            }
            Err(_) => fallback.to_string(),
        }
    } else if referer.starts_with('/') {
        referer.to_string()
    } else {
        fallback.to_string()
    };

    if !raw_path.starts_with(prefix) {
        return fallback.to_string();
    }

    if let Some((path, query)) = raw_path.split_once('?') {
        let mut kept = Vec::new();
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = k.as_ref();
            if kept_keys.contains(&key) {
                kept.push((k.into_owned(), v.into_owned()));
            }
        }
        if kept.is_empty() {
            path.to_string()
        } else {
            let qs = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(kept.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .finish();
            format!("{path}?{qs}")
        }
    } else {
        raw_path
    }
}

fn render_template<T: Template>(tmpl: T) -> Response {
    match tmpl.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {e}"),
        )
            .into_response(),
    }
}

fn random_onboarding_token() -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn onboarding_token_hash(token: &str) -> String {
    use base64::Engine as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn sanitize_admin_next(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let path = if raw.starts_with("http://") || raw.starts_with("https://") {
        let url = Url::parse(raw).ok()?;
        let mut out = url.path().to_string();
        if let Some(query) = url.query() {
            out.push('?');
            out.push_str(query);
        }
        out
    } else {
        raw.to_string()
    };

    if !path.starts_with("/admin/ui") || path.starts_with("/admin/ui/login") {
        return None;
    }
    Some(path)
}

fn admin_next_from_referer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_admin_next)
}

fn admin_login_url(headers: &HeaderMap, error: Option<&str>) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    if let Some(error) = error {
        params.append_pair("error", error);
    }
    if let Some(next) = admin_next_from_referer(headers) {
        params.append_pair("next", &next);
    }
    let query = params.finish();
    if query.is_empty() {
        "/admin/ui/login".to_string()
    } else {
        format!("/admin/ui/login?{query}")
    }
}

fn build_federated_csrf_cookie(token: Option<&str>, secure: bool) -> String {
    let value = token.unwrap_or("");
    let mut cookie = format!(
        "federated_invite_csrf={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        value,
        if token.is_some() { 600 } else { 0 }
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .map(|part| part.trim())
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
        .map(|v| v.to_string())
}

async fn resolve_federated_invitation(
    db_pool: &DbPool,
    raw_token: &str,
) -> Result<Option<FederatedInvitationResolvedRow>, sqlx::Error> {
    let token_hash = onboarding_token_hash(raw_token.trim());
    sqlx::query_as::<_, FederatedInvitationResolvedRow>(
        r#"
        SELECT
            u.id AS user_id,
            u.tenant_id,
            u.email,
            u.is_active,
            u.auth_mode,
            ip.id AS idp_id,
            ip.slug AS provider_slug,
            ip.provider_type,
            ip.issuer,
            ip.client_id,
            ip.client_secret_encrypted,
            ip.auth_url,
            ip.token_url,
            ip.scopes,
            ip.hd_domain,
            t.token_hash,
            t.expires_at,
            t.used_at
        FROM federated_invitation_tokens t
        JOIN users u ON u.id = t.user_id
        JOIN identity_providers ip ON ip.id = t.idp_id
        WHERE t.token_hash = $1
          AND u.deleted_at IS NULL
          AND ip.deleted_at IS NULL
          AND ip.is_active = true
        LIMIT 1
        "#,
    )
    .bind(token_hash)
    .fetch_optional(db_pool)
    .await
}

async fn resolve_federated_discovery(
    row: &FederatedInvitationResolvedRow,
) -> Result<FederatedDiscoveryResponse, String> {
    if let (Some(auth), Some(token)) = (&row.auth_url, &row.token_url) {
        return Ok(FederatedDiscoveryResponse {
            authorization_endpoint: auth.clone(),
            token_endpoint: token.clone(),
            userinfo_endpoint: None,
        });
    }

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        row.issuer.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .get(discovery_url)
        .send()
        .await
        .map_err(|e| format!("OIDC discovery request failed: {e}"))?;
    let resp = resp
        .error_for_status()
        .map_err(|e| format!("OIDC discovery non-success response: {e}"))?;
    resp.json::<FederatedDiscoveryResponse>()
        .await
        .map_err(|e| format!("OIDC discovery parse failed: {e}"))
}

fn session_id_from_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .map(|part| part.trim())
        .find_map(|p| p.strip_prefix(&format!("{ADMIN_SESSION_COOKIE}=")))
        .map(|s| s.to_string())
}

async fn validate_admin_token(state: &WebAdminState, token: &str) -> bool {
    if let Some(root) = &state.admin_auth.admin_root_token {
        if token == root {
            return true;
        }
    }

    let audiences = match sqlx::query_scalar::<_, String>(
        "SELECT client_id FROM oauth_clients WHERE is_active = true AND deleted_at IS NULL",
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) if !v.is_empty() => v,
        _ => return false,
    };

    let claims = match state
        .admin_auth
        .jwt_service
        .verify_access_token(token, &audiences, &[])
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    if claims.groups.contains(&"simple-idm:role:admin".to_string()) {
        return true;
    }
    if state.admin_auth.allow_legacy_admin_group && claims.groups.contains(&"admin".to_string()) {
        return true;
    }
    if state.admin_auth.allow_admin_substring_claim {
        return claims
            .custom_claims
            .keys()
            .any(|k| k.starts_with("admin") || k.contains("admin"));
    }
    false
}

async fn require_admin_token(
    state: &WebAdminState,
    headers: &HeaderMap,
) -> Result<String, Redirect> {
    let Some(session_id) = session_id_from_cookie(headers) else {
        return Err(Redirect::to(&admin_login_url(headers, None)));
    };

    let session = {
        let sessions = state.admin_sessions.read().await;
        sessions.get(&session_id).cloned()
    };
    let Some((token, expires_at)) = session else {
        return Err(Redirect::to(&admin_login_url(headers, None)));
    };
    if Utc::now() >= expires_at {
        let mut sessions = state.admin_sessions.write().await;
        sessions.remove(&session_id);
        return Err(Redirect::to(&admin_login_url(
            headers,
            Some("Session expired"),
        )));
    }

    if validate_admin_token(state, &token).await {
        Ok(token)
    } else {
        let mut sessions = state.admin_sessions.write().await;
        sessions.remove(&session_id);
        Err(Redirect::to(&admin_login_url(
            headers,
            Some("Invalid admin token"),
        )))
    }
}

async fn ui_dashboard(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let users_total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
            .fetch_one(&state.db_pool)
            .await
            .unwrap_or(0);
    let users_active = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND is_active = true",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);
    let users_local = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND auth_mode = 'local'",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);
    let users_ad = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND auth_mode = 'ad'",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);
    let users_federated = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND auth_mode = 'federated'",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);
    let groups_total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM groups WHERE deleted_at IS NULL")
            .fetch_one(&state.db_pool)
            .await
            .unwrap_or(0);
    let clients_total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oauth_clients WHERE deleted_at IS NULL")
            .fetch_one(&state.db_pool)
            .await
            .unwrap_or(0);
    let providers_total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM identity_providers WHERE deleted_at IS NULL",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);
    let claim_maps_total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claim_maps WHERE deleted_at IS NULL")
            .fetch_one(&state.db_pool)
            .await
            .unwrap_or(0);
    let managed_domains = sqlx::query_scalar::<_, String>(
        r#"
        SELECT domain
        FROM tenant_domains
        WHERE is_active = true
        ORDER BY domain ASC
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    render_template(DashboardTemplate {
        sections: nav_items(AdminSection::Dashboard),
        message: query.message,
        error: query.error,
        users_total,
        users_active,
        users_local,
        users_ad,
        users_federated,
        groups_total,
        clients_total,
        providers_total,
        claim_maps_total,
        managed_domains,
    })
}

async fn audit_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let filter_action = query.action.unwrap_or_default();
    let filter_resource_type = query.resource_type.unwrap_or_default();
    let filter_outcome = match query.outcome.unwrap_or_default().as_str() {
        "success" => "success".to_string(),
        "failure" => "failure".to_string(),
        _ => String::new(),
    };
    let filter_q = query.q.unwrap_or_default();
    let filter_range = match query.range.unwrap_or_else(|| "all".to_string()).as_str() {
        "1h" => "1h".to_string(),
        "24h" => "24h".to_string(),
        "7d" => "7d".to_string(),
        "30d" => "30d".to_string(),
        "all" => "all".to_string(),
        _ => "24h".to_string(),
    };

    let rows = match sqlx::query_as::<_, AuditEventRow>(
        r#"
        SELECT created_at, action, resource_type, resource_id, outcome, actor_sub, actor_client_id, details
        FROM audit_events
        WHERE ($1::text = '' OR action ILIKE '%' || $1 || '%')
          AND ($2::text = '' OR resource_type ILIKE '%' || $2 || '%')
          AND ($3::text = '' OR outcome = $3)
          AND (
            $4::text = '' OR
            COALESCE(actor_sub, '') ILIKE '%' || $4 || '%' OR
            COALESCE(actor_client_id, '') ILIKE '%' || $4 || '%' OR
            COALESCE(details::text, '') ILIKE '%' || $4 || '%'
          )
          AND (
            $5::text = 'all' OR
            ($5::text = '1h' AND created_at >= NOW() - INTERVAL '1 hour') OR
            ($5::text = '24h' AND created_at >= NOW() - INTERVAL '24 hours') OR
            ($5::text = '7d' AND created_at >= NOW() - INTERVAL '7 days') OR
            ($5::text = '30d' AND created_at >= NOW() - INTERVAL '30 days')
          )
        ORDER BY created_at DESC
        LIMIT 200
        "#,
    )
    .bind(filter_action.trim())
    .bind(filter_resource_type.trim())
    .bind(filter_outcome.trim())
    .bind(filter_q.trim())
    .bind(filter_range.trim())
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/audit", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    render_template(AuditTemplate {
        sections: nav_items(AdminSection::Audit),
        message: query.message,
        error: query.error,
        rows,
        filter_action,
        filter_resource_type,
        filter_outcome,
        filter_q,
        filter_range,
    })
}

async fn login_page(Query(query): Query<PageQuery>) -> Response {
    let next = query
        .next
        .as_deref()
        .and_then(sanitize_admin_next)
        .unwrap_or_else(|| "/admin/ui/".to_string());
    render_template(LoginTemplate {
        error: query.error.as_deref(),
        next,
    })
}

async fn login_submit(State(state): State<WebAdminState>, Form(form): Form<LoginForm>) -> Response {
    if !validate_admin_token(&state, &form.token).await {
        return Redirect::to("/admin/ui/login?error=Invalid%20admin%20token").into_response();
    }

    let session_id = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect::<String>();
    let expires_at = Utc::now() + chrono::Duration::seconds(ADMIN_SESSION_TTL_SECONDS);
    {
        let mut sessions = state.admin_sessions.write().await;
        sessions.insert(session_id.clone(), (form.token, expires_at));
    }

    let secure = if state.secure_cookies { "; Secure" } else { "" };
    let cookie = format!(
        "{ADMIN_SESSION_COOKIE}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{}",
        session_id, ADMIN_SESSION_TTL_SECONDS, secure
    );

    let next = form
        .next
        .as_deref()
        .and_then(sanitize_admin_next)
        .unwrap_or_else(|| "/admin/ui/".to_string());

    ([(header::SET_COOKIE, cookie)], Redirect::to(&next)).into_response()
}

async fn logout_submit(State(state): State<WebAdminState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = session_id_from_cookie(&headers) {
        let mut sessions = state.admin_sessions.write().await;
        sessions.remove(&session_id);
    }
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    let cookie = format!(
        "{ADMIN_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{}",
        secure
    );
    (
        [(header::SET_COOKIE, cookie)],
        Redirect::to("/admin/ui/login"),
    )
        .into_response()
}

async fn ad_onboarding_page(Query(query): Query<AdOnboardingQuery>) -> Response {
    let token = query.token.unwrap_or_default();
    render_template(AdOnboardingTemplate {
        message: query.message,
        error: query.error,
        token,
    })
}

async fn ad_onboarding_submit(
    State(state): State<WebAdminState>,
    Form(form): Form<AdOnboardingForm>,
) -> Response {
    if form.token.trim().is_empty() {
        simple_idm_core::audit::emit_event(
            &state.db_pool,
            "ad.onboarding.submit",
            "ad_onboarding",
            None,
            "failure",
            Some(serde_json::json!({"reason":"missing_token"})),
        )
        .await;
        return redirect_with("/ad/onboarding", "error", "Missing onboarding token")
            .into_response();
    }
    if form.login.trim().is_empty() {
        return redirect_with(
            &format!(
                "/ad/onboarding?token={}",
                urlencoding::encode(form.token.trim())
            ),
            "error",
            "Missing AD login",
        )
        .into_response();
    }
    if form.password.is_empty() {
        return redirect_with(
            &format!(
                "/ad/onboarding?token={}",
                urlencoding::encode(form.token.trim())
            ),
            "error",
            "Missing AD password",
        )
        .into_response();
    }

    let token_hash = onboarding_token_hash(form.token.trim());
    let row = match sqlx::query(
        r#"
        SELECT t.user_id, t.idp_id, u.id, u.username, u.tenant_id, t.expires_at, t.used_at
        FROM ad_onboarding_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1
        LIMIT 1
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            simple_idm_core::audit::emit_event(
                &state.db_pool,
                "ad.onboarding.submit",
                "ad_onboarding",
                None,
                "failure",
                Some(serde_json::json!({"reason":"invalid_token"})),
            )
            .await;
            return redirect_with("/ad/onboarding", "error", "Invalid onboarding token")
                .into_response();
        }
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let expires_at = match row.try_get::<DateTime<Utc>, _>("expires_at") {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };
    let used_at = match row.try_get::<Option<DateTime<Utc>>, _>("used_at") {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };
    if used_at.is_some() {
        simple_idm_core::audit::emit_event(
            &state.db_pool,
            "ad.onboarding.submit",
            "ad_onboarding",
            None,
            "failure",
            Some(serde_json::json!({"reason":"token_used"})),
        )
        .await;
        return redirect_with(
            "/ad/onboarding",
            "error",
            "Onboarding token was already used",
        )
        .into_response();
    }
    if Utc::now() > expires_at {
        simple_idm_core::audit::emit_event(
            &state.db_pool,
            "ad.onboarding.submit",
            "ad_onboarding",
            None,
            "failure",
            Some(serde_json::json!({"reason":"token_expired"})),
        )
        .await;
        return redirect_with("/ad/onboarding", "error", "Onboarding token expired")
            .into_response();
    }

    let idp_id = match row.try_get::<Uuid, _>("idp_id") {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };
    let provider = match oauth2::load_ad_ldap_provider(&state.db_pool, idp_id).await {
        Ok(v) => v,
        Err(e) => {
            return redirect_with(
                "/ad/onboarding",
                "error",
                &format!("AD provider error: {e}"),
            )
            .into_response();
        }
    };

    if let Err(e) = simple_idm_ad_auth::verify_ldap_password(
        &provider.config,
        form.login.trim(),
        &form.password,
    )
    .await
    {
        simple_idm_core::audit::emit_event(
            &state.db_pool,
            "ad.onboarding.submit",
            "ad_onboarding",
            None,
            "failure",
            Some(serde_json::json!({"reason":"ldap_auth_failed","error": e.to_string()})),
        )
        .await;
        return redirect_with(
            &format!(
                "/ad/onboarding?token={}",
                urlencoding::encode(form.token.trim())
            ),
            "error",
            &format!("AD login failed: {e}"),
        )
        .into_response();
    }

    let user_id = match row.try_get::<Uuid, _>("user_id") {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };
    let user = match sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return redirect_with("/ad/onboarding", "error", "User not found").into_response();
        }
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    if let Err(e) = oauth2::sync_ldap_roles_force_with_provider(
        state.oauth_state.as_ref(),
        &user,
        form.login.trim(),
        &provider,
    )
    .await
    {
        simple_idm_core::audit::emit_event(
            &state.db_pool,
            "ad.onboarding.submit",
            "ad_onboarding",
            Some(user.id),
            "failure",
            Some(serde_json::json!({"reason":"ldap_role_sync_failed","error": e.to_string()})),
        )
        .await;
        return redirect_with(
            &format!(
                "/ad/onboarding?token={}",
                urlencoding::encode(form.token.trim())
            ),
            "error",
            &format!("AD role sync failed: {e}"),
        )
        .into_response();
    }

    if let Err(e) =
        sqlx::query("UPDATE ad_onboarding_tokens SET used_at = NOW() WHERE token_hash = $1")
            .bind(onboarding_token_hash(form.token.trim()))
            .execute(&state.db_pool)
            .await
    {
        simple_idm_core::audit::emit_event(
            &state.db_pool,
            "ad.onboarding.submit",
            "ad_onboarding",
            Some(user.id),
            "failure",
            Some(serde_json::json!({"reason":"mark_used_failed","error": e.to_string()})),
        )
        .await;
        return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}")).into_response();
    }

    simple_idm_core::audit::emit_event(
        &state.db_pool,
        "ad.onboarding.submit",
        "ad_onboarding",
        Some(user.id),
        "success",
        Some(serde_json::json!({"login": form.login.trim()})),
    )
    .await;

    redirect_with(
        "/ad/onboarding",
        "message",
        "AD onboarding completed. You can close this page.",
    )
    .into_response()
}

async fn federated_onboarding_start(
    State(state): State<WebAdminState>,
    Query(query): Query<FederatedOnboardingQuery>,
) -> Response {
    let Some(raw_token) = query
        .token
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        return Html(simple_idm_core::oauth2::templates::error_page(
            "invalid_request",
            "Missing invitation token",
        ))
        .into_response();
    };

    let row = match resolve_federated_invitation(&state.db_pool, raw_token).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Html(simple_idm_core::oauth2::templates::error_page(
                "invalid_request",
                "Invalid invitation token",
            ))
            .into_response();
        }
        Err(e) => {
            return Html(simple_idm_core::oauth2::templates::error_page(
                "server_error",
                &format!("DB error: {e}"),
            ))
            .into_response();
        }
    };

    if !row.is_active || !row.auth_mode.eq_ignore_ascii_case("federated") {
        return Html(simple_idm_core::oauth2::templates::error_page(
            "access_denied",
            "User is not eligible for federated onboarding",
        ))
        .into_response();
    }
    if row.used_at.is_some() {
        return Html(simple_idm_core::oauth2::templates::error_page(
            "invalid_request",
            "Invitation token was already used",
        ))
        .into_response();
    }
    if row.expires_at < Utc::now() {
        return Html(simple_idm_core::oauth2::templates::error_page(
            "invalid_request",
            "Invitation token expired",
        ))
        .into_response();
    }

    let discovery = match resolve_federated_discovery(&row).await {
        Ok(v) => v,
        Err(e) => {
            return Html(simple_idm_core::oauth2::templates::error_page(
                "server_error",
                &e,
            ))
            .into_response();
        }
    };

    let csrf: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let payload = FederatedInviteStatePayload {
        csrf: csrf.clone(),
        token_hash: row.token_hash.clone(),
        provider_slug: row.provider_slug.clone(),
    };
    let state_token = match serde_json::to_vec(&payload) {
        Ok(v) => URL_SAFE_NO_PAD.encode(v),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to prepare federated onboarding state",
            )
                .into_response();
        }
    };

    let issuer =
        std::env::var("JWT_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let callback = format!(
        "{}/federated/onboarding/{}/callback",
        issuer.trim_end_matches('/'),
        row.provider_slug
    );
    let mut auth_url = match Url::parse(&discovery.authorization_endpoint) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid upstream authorization endpoint",
            )
                .into_response();
        }
    };
    let scope = if row.scopes.is_empty() {
        "openid profile email".to_string()
    } else {
        row.scopes.join(" ")
    };
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &row.client_id)
        .append_pair("redirect_uri", &callback)
        .append_pair("scope", &scope)
        .append_pair("login_hint", &row.email)
        .append_pair("state", &state_token);
    if row.provider_type.eq_ignore_ascii_case("google")
        || row
            .issuer
            .trim_end_matches('/')
            .eq_ignore_ascii_case("https://accounts.google.com")
    {
        auth_url
            .query_pairs_mut()
            .append_pair("prompt", "select_account");
    }
    if let Some(domain) = &row.hd_domain {
        auth_url.query_pairs_mut().append_pair("hd", domain);
    }

    let cookie = build_federated_csrf_cookie(Some(&csrf), state.secure_cookies);
    (
        [(header::SET_COOKIE, cookie)],
        Redirect::to(auth_url.as_ref()),
    )
        .into_response()
}

async fn federated_onboarding_callback(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let code = match params
        .get("code")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        Some(v) => v.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Missing authorization code from upstream provider",
            )
                .into_response();
        }
    };
    let state_token = match params
        .get("state")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, "Missing state parameter").into_response(),
    };

    let payload: FederatedInviteStatePayload = match URL_SAFE_NO_PAD
        .decode(state_token)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, "Invalid state parameter").into_response(),
    };

    if payload.provider_slug != provider {
        return (StatusCode::BAD_REQUEST, "Provider mismatch").into_response();
    }

    let cookie_csrf = cookie_value(&headers, "federated_invite_csrf").unwrap_or_default();
    if cookie_csrf.is_empty() || cookie_csrf != payload.csrf {
        return (StatusCode::BAD_REQUEST, "CSRF verification failed").into_response();
    }

    let row = match sqlx::query_as::<_, FederatedInvitationResolvedRow>(
        r#"
        SELECT
            u.id AS user_id,
            u.tenant_id,
            u.email,
            u.is_active,
            u.auth_mode,
            ip.id AS idp_id,
            ip.slug AS provider_slug,
            ip.provider_type,
            ip.issuer,
            ip.client_id,
            ip.client_secret_encrypted,
            ip.auth_url,
            ip.token_url,
            ip.scopes,
            ip.hd_domain,
            t.token_hash,
            t.expires_at,
            t.used_at
        FROM federated_invitation_tokens t
        JOIN users u ON u.id = t.user_id
        JOIN identity_providers ip ON ip.id = t.idp_id
        WHERE t.token_hash = $1
          AND ip.slug = $2
          AND u.deleted_at IS NULL
          AND ip.deleted_at IS NULL
          AND ip.is_active = true
        LIMIT 1
        "#,
    )
    .bind(&payload.token_hash)
    .bind(provider.trim())
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return (StatusCode::BAD_REQUEST, "Invalid invitation token").into_response(),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
        }
    };

    if row.used_at.is_some() {
        return (StatusCode::BAD_REQUEST, "Invitation token was already used").into_response();
    }
    if row.expires_at < Utc::now() {
        return (StatusCode::BAD_REQUEST, "Invitation token expired").into_response();
    }
    if !row.is_active || !row.auth_mode.eq_ignore_ascii_case("federated") {
        return (
            StatusCode::BAD_REQUEST,
            "User is not eligible for federated onboarding",
        )
            .into_response();
    }

    let discovery = match resolve_federated_discovery(&row).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, e).into_response(),
    };

    let issuer =
        std::env::var("JWT_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let callback = format!(
        "{}/federated/onboarding/{}/callback",
        issuer.trim_end_matches('/'),
        provider.trim()
    );
    let client_secret = match decrypt_secret(&row.client_secret_encrypted) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to decrypt upstream client secret: {e}"),
            )
                .into_response();
        }
    };

    let token_resp = {
        let resp = match reqwest::Client::new()
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", callback.as_str()),
                ("client_id", row.client_id.as_str()),
                ("client_secret", client_secret.as_str()),
            ])
            .send()
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to exchange code with upstream IdP: {e}"),
                )
                    .into_response();
            }
        };
        let resp = match resp.error_for_status() {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Upstream IdP rejected token request: {e}"),
                )
                    .into_response();
            }
        };
        match resp.json::<FederatedTokenResponse>().await {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to parse token response: {e}"),
                )
                    .into_response();
            }
        }
    };

    let userinfo_endpoint = match discovery.userinfo_endpoint {
        Some(v) => v,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                "Upstream IdP userinfo endpoint is missing",
            )
                .into_response();
        }
    };
    let userinfo = {
        let resp = match reqwest::Client::new()
            .get(&userinfo_endpoint)
            .bearer_auth(&token_resp.access_token)
            .send()
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to load userinfo from upstream IdP: {e}"),
                )
                    .into_response();
            }
        };
        let resp = match resp.error_for_status() {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Upstream IdP rejected userinfo request: {e}"),
                )
                    .into_response();
            }
        };
        match resp.json::<FederatedUserInfoResponse>().await {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to parse userinfo from upstream IdP: {e}"),
                )
                    .into_response();
            }
        }
    };

    let email = userinfo
        .email
        .clone()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if email.is_empty() || !userinfo.email_verified.unwrap_or(false) {
        return (
            StatusCode::FORBIDDEN,
            "Verified email is required for federated onboarding",
        )
            .into_response();
    }
    if email != row.email.to_lowercase() {
        return (
            StatusCode::FORBIDDEN,
            "Google account email does not match the invited Simple IDM user",
        )
            .into_response();
    }

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
        }
    };

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO user_identities (
            tenant_id, user_id, idp_id, issuer, subject, email_at_link, email_verified,
            last_login_at, approval_status
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), 'pending')
        ON CONFLICT (tenant_id, issuer, subject)
        WHERE deleted_at IS NULL
        DO UPDATE SET
            email_at_link = EXCLUDED.email_at_link,
            email_verified = EXCLUDED.email_verified,
            last_login_at = NOW(),
            approval_status = CASE
                WHEN user_identities.approval_status = 'approved' THEN 'approved'
                ELSE 'pending'
            END,
            approved_at = CASE
                WHEN user_identities.approval_status = 'approved' THEN user_identities.approved_at
                ELSE NULL
            END,
            rejected_at = NULL,
            updated_at = NOW()
        "#,
    )
    .bind(row.tenant_id)
    .bind(row.user_id)
    .bind(row.idp_id)
    .bind(&row.issuer)
    .bind(&userinfo.sub)
    .bind(&email)
    .bind(userinfo.email_verified)
    .execute(&mut *tx)
    .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
    }

    if let Err(e) =
        sqlx::query("UPDATE federated_invitation_tokens SET used_at = NOW() WHERE token_hash = $1")
            .bind(&row.token_hash)
            .execute(&mut *tx)
            .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
    }

    if let Err(e) = tx.commit().await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response();
    }

    simple_idm_core::audit::emit_event(
        &state.db_pool,
        "federated.onboarding.complete",
        "user_identities",
        Some(row.user_id),
        "success",
        Some(json!({
            "provider": row.provider_slug,
            "provider_type": row.provider_type,
            "issuer": row.issuer,
            "subject": userinfo.sub,
            "email": email
        })),
    )
    .await;

    let clear_cookie = build_federated_csrf_cookie(None, state.secure_cookies);
    let body = render_template(FederatedOnboardingCompleteTemplate {
        message: "Federated onboarding completed. Waiting for admin approval.",
    });
    let mut response = body;
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_cookie.parse().unwrap());
    response
}

async fn users_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let filter_q = query.q.unwrap_or_default();
    let filter_note = query.note.unwrap_or_default();
    let filter_status = query.status.unwrap_or_else(|| "all".to_string());
    let page = query.page.unwrap_or(1).max(1);
    let per_page: i64 = 25;
    let search_patterns = filter_q
        .split_whitespace()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
        .map(|v| format!("%{v}%"))
        .collect::<Vec<_>>();
    let selected_letters = query
        .letters
        .unwrap_or_default()
        .into_iter()
        .flat_map(|raw| {
            raw.split(',')
                .map(|v| v.trim().to_uppercase())
                .filter(|v| v.len() == 1 && v.chars().all(|c| c.is_ascii_alphabetic()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let active_filter = match filter_status.as_str() {
        "active" => Some(true),
        "inactive" => Some(false),
        _ => None,
    };

    let total_items = match sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*)
           FROM users
           WHERE deleted_at IS NULL
             AND (
               cardinality($1::text[]) = 0 OR
               LOWER(
                 CONCAT_WS(
                   ' ',
                   username,
                   email,
                   COALESCE(first_name, ''),
                   COALESCE(last_name, ''),
                   COALESCE(
                     (
                       SELECT uei.external_user_id
                       FROM user_external_identities uei
                       WHERE uei.user_id = users.id
                         AND uei.source = 'ad'
                         AND uei.idp_id = users.auth_provider_id
                         AND uei.deleted_at IS NULL
                       LIMIT 1
                     ),
                     ''
                   ),
                   COALESCE(
                     (
                       SELECT uei.login_name
                       FROM user_external_identities uei
                       WHERE uei.user_id = users.id
                         AND uei.source = 'ad'
                         AND uei.idp_id = users.auth_provider_id
                         AND uei.deleted_at IS NULL
                       LIMIT 1
                     ),
                     ''
                   ),
                   COALESCE(
                     (
                       SELECT uei.upn
                       FROM user_external_identities uei
                       WHERE uei.user_id = users.id
                         AND uei.source = 'ad'
                         AND uei.idp_id = users.auth_provider_id
                         AND uei.deleted_at IS NULL
                       LIMIT 1
                     ),
                     ''
                   )
                 )
               )
                 LIKE ALL($1::text[])
             )
             AND ($2::boolean IS NULL OR is_active = $2)
             AND ($3::text IS NULL OR $3 = '' OR COALESCE(note, '') ILIKE '%' || $3 || '%')
             AND (
               cardinality($4::text[]) = 0 OR
               UPPER(LEFT(COALESCE(last_name, ''), 1)) = ANY($4::text[])
             )"#,
    )
    .bind(&search_patterns)
    .bind(active_filter)
    .bind(filter_note.trim())
    .bind(&selected_letters)
    .fetch_one(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let total_pages = ((total_items + per_page - 1) / per_page).max(1) as u32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * per_page;

    let rows = match sqlx::query_as::<_, UserRow>(
        r#"SELECT
             users.id,
             users.username,
             users.email,
             users.first_name,
             users.last_name,
             users.recovery_email,
             users.phone_e164,
             users.last_sign_in_at,
             users.note,
             users.auth_mode,
             users.auth_provider_id,
             aip.slug AS auth_provider_slug,
             users.is_active,
             uei.external_user_id,
             uei.external_user_id_type,
             uei.login_name AS external_login_name,
             uei.upn AS external_upn,
             uei.last_seen_at AS external_last_seen_at,
             fui.federated_provider_slug,
             fui.federated_provider_type,
             fui.federated_subject,
             fui.federated_approval_status,
             COALESCE(
               (
                 SELECT ua.status
                 FROM user_authenticators ua
                 WHERE ua.user_id = users.id
                   AND ua.kind = 'totp'
                   AND ua.status IN ('active', 'pending')
                 ORDER BY CASE ua.status WHEN 'active' THEN 0 ELSE 1 END, ua.updated_at DESC
                 LIMIT 1
               ),
               'not_enrolled'
             ) AS mfa_status,
             (
               SELECT COUNT(*)
               FROM user_recovery_codes urc
               WHERE urc.user_id = users.id AND urc.used_at IS NULL
             ) AS recovery_codes_remaining
           FROM users
           LEFT JOIN identity_providers aip ON aip.id = users.auth_provider_id AND aip.deleted_at IS NULL
           LEFT JOIN user_external_identities uei
             ON uei.user_id = users.id
            AND uei.source = 'ad'
            AND uei.idp_id = users.auth_provider_id
            AND uei.deleted_at IS NULL
           LEFT JOIN LATERAL (
             SELECT
               ip.slug AS federated_provider_slug,
               ip.provider_type AS federated_provider_type,
               ui.subject AS federated_subject,
               ui.approval_status AS federated_approval_status
             FROM user_identities ui
             JOIN identity_providers ip ON ip.id = ui.idp_id
             WHERE ui.user_id = users.id
               AND ui.deleted_at IS NULL
               AND ip.deleted_at IS NULL
             ORDER BY ui.updated_at DESC, ui.created_at DESC
             LIMIT 1
           ) fui ON TRUE
           WHERE users.deleted_at IS NULL
             AND (
               cardinality($1::text[]) = 0 OR
               LOWER(
                 CONCAT_WS(
                   ' ',
                   users.username,
                   users.email,
                   COALESCE(users.first_name, ''),
                   COALESCE(users.last_name, ''),
                   COALESCE(uei.external_user_id, ''),
                   COALESCE(uei.login_name, ''),
                   COALESCE(uei.upn, '')
                 )
               )
                 LIKE ALL($1::text[])
             )
             AND ($2::boolean IS NULL OR users.is_active = $2)
             AND ($3::text IS NULL OR $3 = '' OR COALESCE(users.note, '') ILIKE '%' || $3 || '%')
             AND (
               cardinality($4::text[]) = 0 OR
               UPPER(LEFT(COALESCE(users.last_name, ''), 1)) = ANY($4::text[])
             )
           ORDER BY users.username ASC
           LIMIT $5 OFFSET $6"#,
    )
    .bind(&search_patterns)
    .bind(active_filter)
    .bind(filter_note.trim())
    .bind(&selected_letters)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}")).into_response();
        }
    };

    let letter_filters = ('A'..='Z')
        .map(|ch| {
            let v = ch.to_string();
            LetterFilter {
                selected: selected_letters.contains(&v),
                value: v,
            }
        })
        .collect::<Vec<_>>();

    let letters_csv = selected_letters.join(",");
    let common_qs = format!(
        "q={}&status={}&note={}",
        urlencoding::encode(filter_q.trim()),
        urlencoding::encode(&filter_status),
        urlencoding::encode(filter_note.trim())
    );
    let prev_page = page.saturating_sub(1).max(1);
    let next_page = (page + 1).min(total_pages.max(1));
    let prev_page_url = if letters_csv.is_empty() {
        format!("/admin/ui/users?{}&page={}", common_qs, prev_page)
    } else {
        format!(
            "/admin/ui/users?{}&letters={}&page={}",
            common_qs,
            urlencoding::encode(&letters_csv),
            prev_page
        )
    };
    let next_page_url = if letters_csv.is_empty() {
        format!("/admin/ui/users?{}&page={}", common_qs, next_page)
    } else {
        format!(
            "/admin/ui/users?{}&letters={}&page={}",
            common_qs,
            urlencoding::encode(&letters_csv),
            next_page
        )
    };

    let deleted_rows = sqlx::query_as::<_, UserRow>(
        r#"SELECT
             users.id,
             users.username,
             users.email,
             users.first_name,
             users.last_name,
             users.recovery_email,
             users.phone_e164,
             users.last_sign_in_at,
             users.note,
             users.auth_mode,
             users.auth_provider_id,
             aip.slug AS auth_provider_slug,
             users.is_active,
             uei.external_user_id,
             uei.external_user_id_type,
             uei.login_name AS external_login_name,
             uei.upn AS external_upn,
             uei.last_seen_at AS external_last_seen_at,
             fui.federated_provider_slug,
             fui.federated_provider_type,
             fui.federated_subject,
             fui.federated_approval_status,
             COALESCE(
               (
                 SELECT ua.status
                 FROM user_authenticators ua
                 WHERE ua.user_id = users.id
                   AND ua.kind = 'totp'
                   AND ua.status IN ('active', 'pending')
                 ORDER BY CASE ua.status WHEN 'active' THEN 0 ELSE 1 END, ua.updated_at DESC
                 LIMIT 1
               ),
               'not_enrolled'
             ) AS mfa_status,
             (
               SELECT COUNT(*)
               FROM user_recovery_codes urc
               WHERE urc.user_id = users.id AND urc.used_at IS NULL
             ) AS recovery_codes_remaining
           FROM users
           LEFT JOIN identity_providers aip ON aip.id = users.auth_provider_id AND aip.deleted_at IS NULL
           LEFT JOIN user_external_identities uei
             ON uei.user_id = users.id
            AND uei.source = 'ad'
            AND uei.idp_id = users.auth_provider_id
            AND uei.deleted_at IS NULL
           LEFT JOIN LATERAL (
             SELECT
               ip.slug AS federated_provider_slug,
               ip.provider_type AS federated_provider_type,
               ui.subject AS federated_subject,
               ui.approval_status AS federated_approval_status
             FROM user_identities ui
             JOIN identity_providers ip ON ip.id = ui.idp_id
             WHERE ui.user_id = users.id
               AND ui.deleted_at IS NULL
               AND ip.deleted_at IS NULL
             ORDER BY ui.updated_at DESC, ui.created_at DESC
             LIMIT 1
           ) fui ON TRUE
           WHERE users.deleted_at IS NOT NULL
           ORDER BY users.deleted_at DESC
           LIMIT 50"#,
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let ad_user_ids = rows
        .iter()
        .filter(|u| u.auth_mode == "ad")
        .map(|u| u.id)
        .collect::<Vec<_>>();

    let ad_modal_data = if ad_user_ids.is_empty() {
        Vec::new()
    } else {
        let role_rows = sqlx::query(
            r#"
            SELECT user_id, role_name
            FROM user_external_roles
            WHERE source = 'ad'
              AND user_id = ANY($1::uuid[])
              AND idp_id IS NOT NULL
            ORDER BY role_name ASC
            "#,
        )
        .bind(&ad_user_ids)
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();

        let groups = sqlx::query_as::<_, SimpleGroupOption>(
            r#"SELECT id, name FROM groups WHERE deleted_at IS NULL ORDER BY name ASC"#,
        )
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();

        let existing_mappings = sqlx::query_as::<_, ExistingAdMappingRow>(
            r#"
            SELECT
              m.id,
              m.tenant_id,
              m.idp_id,
              m.external_role,
              m.group_id,
              g.name AS group_name,
              m.priority
            FROM external_role_mappings m
            JOIN groups g ON g.id = m.group_id
            WHERE m.source = 'ad'
              AND m.idp_id IS NOT NULL
              AND m.is_active = true
              AND m.deleted_at IS NULL
              AND g.deleted_at IS NULL
            ORDER BY m.external_role ASC, g.name ASC
            "#,
        )
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();

        let mut by_user: BTreeMap<Uuid, Vec<UserAdRoleRow>> = BTreeMap::new();
        for row in role_rows {
            if let (Ok(user_id), Ok(role_name)) = (
                row.try_get::<Uuid, _>("user_id"),
                row.try_get::<String, _>("role_name"),
            ) {
                by_user
                    .entry(user_id)
                    .or_default()
                    .push(UserAdRoleRow { role_name });
            }
        }

        let mut by_user_existing_json: BTreeMap<Uuid, String> = BTreeMap::new();
        let user_lookup = sqlx::query(
            "SELECT id, tenant_id, auth_provider_id FROM users WHERE id = ANY($1::uuid[])",
        )
        .bind(&ad_user_ids)
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();
        let mut tenant_by_user: HashMap<Uuid, (Uuid, Option<Uuid>)> = HashMap::new();
        for r in user_lookup {
            if let (Ok(uid), Ok(tid)) = (
                r.try_get::<Uuid, _>("id"),
                r.try_get::<Uuid, _>("tenant_id"),
            ) {
                let idp_id = r
                    .try_get::<Option<Uuid>, _>("auth_provider_id")
                    .ok()
                    .flatten();
                tenant_by_user.insert(uid, (tid, idp_id));
            }
        }

        for (user_id, roles) in &by_user {
            let role_set = roles
                .iter()
                .map(|r| r.role_name.as_str())
                .collect::<std::collections::HashSet<_>>();
            let Some((user_tenant, user_idp_id)) = tenant_by_user.get(user_id).copied() else {
                by_user_existing_json.insert(*user_id, "[]".to_string());
                continue;
            };
            let items = existing_mappings
                .iter()
                .filter(|m| {
                    m.tenant_id == user_tenant
                        && m.idp_id == user_idp_id
                        && role_set.contains(m.external_role.as_str())
                })
                .map(|m| {
                    json!({
                        "id": m.id,
                        "external_role": m.external_role,
                        "group_id": m.group_id,
                        "group_name": m.group_name,
                        "priority": m.priority
                    })
                })
                .collect::<Vec<_>>();
            let serialized = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
            by_user_existing_json.insert(*user_id, serialized);
        }

        ad_user_ids
            .into_iter()
            .map(|user_id| UserAdMappingModalData {
                user_id,
                ad_roles: by_user.remove(&user_id).unwrap_or_default(),
                groups: groups.clone(),
                existing_mappings_json: by_user_existing_json
                    .remove(&user_id)
                    .unwrap_or_else(|| "[]".to_string()),
            })
            .collect::<Vec<_>>()
    };

    let ad_onboarding_tokens = match sqlx::query_as::<_, AdOnboardingTokenRow>(
        r#"
        SELECT
            t.token_hash,
            u.username,
            u.email,
            t.created_at,
            t.expires_at,
            t.used_at
        FROM ad_onboarding_tokens t
        JOIN users u ON u.id = t.user_id
        ORDER BY t.created_at DESC
        LIMIT 500
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => {
            let now = Utc::now();
            v.into_iter()
                .map(|r| {
                    let (status, status_class) = if r.used_at.is_some() {
                        ("used".to_string(), "bg-green-lt".to_string())
                    } else if r.expires_at < now {
                        ("expired".to_string(), "bg-red-lt".to_string())
                    } else {
                        ("pending".to_string(), "bg-yellow-lt".to_string())
                    };
                    AdOnboardingTokenView {
                        token_hash: r.token_hash,
                        username: r.username,
                        email: r.email,
                        created_at: r.created_at,
                        expires_at: r.expires_at,
                        used_at: r.used_at,
                        status,
                        status_class,
                    }
                })
                .collect::<Vec<_>>()
        }
        Err(_) => Vec::new(),
    };

    let identity_providers = sqlx::query_as::<_, IdentityProviderRow>(
        r#"
        SELECT
          ip.id, ip.slug, ip.provider_type, ip.issuer, ip.client_id, ip.auth_url, ip.token_url, ip.jwks_url, ip.scopes, ip.hd_domain, ip.is_active,
          ad.host AS ad_host,
          ad.port AS ad_port,
          ad.base_dn AS ad_base_dn,
          ad.user_filter AS ad_user_filter,
          ad.tls_mode AS ad_tls_mode,
          ad.timeout_seconds AS ad_timeout_seconds,
          ad.allow_insecure AS ad_allow_insecure,
          ad.domains AS ad_domains,
          ad.bind_dn AS ad_bind_dn,
          ad.role_sync_enabled AS ad_role_sync_enabled,
          ad.role_sync_ttl_seconds AS ad_role_sync_ttl_seconds,
          ad.role_sync_timeout_seconds AS ad_role_sync_timeout_seconds
        FROM identity_providers ip
        LEFT JOIN identity_provider_ad_ldap_configs ad ON ad.idp_id = ip.id
        WHERE ip.tenant_id = $1
          AND ip.is_active = true
          AND ip.deleted_at IS NULL
        ORDER BY slug ASC
        "#,
    )
    .bind(default_tenant_id())
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    render_template(UsersTemplate {
        sections: nav_items(AdminSection::Users),
        message: query.message,
        error: query.error,
        ad_link: query.ad_link,
        federated_link: query.federated_link,
        rows,
        deleted_rows,
        ad_modal_data,
        ad_onboarding_tokens,
        identity_providers,
        filter_q,
        filter_status,
        filter_note,
        letter_filters,
        current_page: page,
        total_pages,
        has_prev: page > 1,
        has_next: page < total_pages,
        prev_page_url,
        next_page_url,
        total_items,
    })
}

async fn ad_onboarding_tokens_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, AdOnboardingTokenRow>(
        r#"
        SELECT
            t.token_hash,
            u.username,
            u.email,
            t.created_at,
            t.expires_at,
            t.used_at
        FROM ad_onboarding_tokens t
        JOIN users u ON u.id = t.user_id
        ORDER BY t.created_at DESC
        LIMIT 200
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    render_template(AdOnboardingTokensTemplate {
        sections: nav_items(AdminSection::Users),
        message: query.message,
        error: query.error,
        rows,
    })
}

async fn ad_roles_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<AdRolesQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let email = query.email.unwrap_or_default().trim().to_lowercase();
    let rows = if email.is_empty() {
        Vec::new()
    } else {
        match sqlx::query_as::<_, ExternalRoleRow>(
            r#"
            SELECT u.email, r.source, r.role_name, r.synced_at
            FROM user_external_roles r
            JOIN users u ON u.id = r.user_id
            WHERE u.email = $1
              AND u.deleted_at IS NULL
            ORDER BY r.role_name ASC
            "#,
        )
        .bind(&email)
        .fetch_all(&state.db_pool)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                return redirect_with("/admin/ui/ad-roles", "error", &format!("DB error: {e}"))
                    .into_response();
            }
        }
    };

    render_template(AdRolesTemplate {
        sections: nav_items(AdminSection::Users),
        message: query.message,
        error: query.error,
        email,
        rows,
    })
}

async fn ad_role_mappings_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, ExternalRoleMappingRow>(
        r#"
        SELECT m.id, m.source, m.external_role, g.name as group_name, m.mode, m.priority, m.is_active
        FROM external_role_mappings m
        JOIN groups g ON g.id = m.group_id
        WHERE m.deleted_at IS NULL
        ORDER BY m.priority ASC, m.external_role ASC
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/ad-role-mappings", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let groups = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, name FROM groups WHERE deleted_at IS NULL ORDER BY name ASC",
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    render_template(AdRoleMappingsTemplate {
        sections: nav_items(AdminSection::Users),
        message: query.message,
        error: query.error,
        rows,
        groups,
    })
}

async fn ad_role_mappings_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<RoleMappingCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let group_id = match Uuid::parse_str(form.group_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            return redirect_with("/admin/ui/ad-role-mappings", "error", "Invalid group_id")
                .into_response();
        }
    };
    let mode = match form.mode.trim() {
        "add" | "remove" => form.mode.trim().to_string(),
        _ => "add".to_string(),
    };
    let priority = form.priority.unwrap_or(100);
    let source = if form.source.trim().is_empty() {
        "ad".to_string()
    } else {
        form.source.trim().to_lowercase()
    };

    let result = sqlx::query(
        r#"
        INSERT INTO external_role_mappings (tenant_id, source, external_role, group_id, mode, priority, is_active)
        VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5, true)
        "#,
    )
    .bind(source)
    .bind(form.external_role.trim())
    .bind(group_id)
    .bind(mode)
    .bind(priority)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(
            "/admin/ui/ad-role-mappings",
            "message",
            "Role mapping created",
        )
        .into_response(),
        Err(e) => redirect_with(
            "/admin/ui/ad-role-mappings",
            "error",
            &format!("Create failed: {e}"),
        )
        .into_response(),
    }
}

async fn ad_role_mappings_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(
        r#"
        UPDATE external_role_mappings
        SET is_active = false, deleted_at = NOW(), updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(
            "/admin/ui/ad-role-mappings",
            "message",
            "Role mapping deactivated",
        )
        .into_response(),
        Err(e) => redirect_with(
            "/admin/ui/ad-role-mappings",
            "error",
            &format!("Deactivate failed: {e}"),
        )
        .into_response(),
    }
}

async fn users_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<UserCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let email = form.email.trim().to_lowercase();
    if !looks_like_email(&email) {
        return redirect_with(&return_path, "error", "Invalid email format").into_response();
    }
    let recovery_email = normalize_opt_form(form.recovery_email).map(|v| v.to_lowercase());
    if let Some(value) = recovery_email.as_deref() {
        if !looks_like_email(value) {
            return redirect_with(&return_path, "error", "Invalid recovery email format")
                .into_response();
        }
    }
    let phone_e164 = normalize_opt_form(form.phone_e164);
    if let Some(value) = phone_e164.as_deref() {
        if !looks_like_e164(value) {
            return redirect_with(
                &return_path,
                "error",
                "Phone must use E.164 format, e.g. +420...",
            )
            .into_response();
        }
    }
    let first_name = normalize_opt_form(form.first_name);
    let last_name = normalize_opt_form(form.last_name);
    let note = normalize_opt_form(form.note);
    let auth_mode = normalize_auth_mode(form.auth_mode.as_deref());
    let auth_provider_id = if auth_mode.eq_ignore_ascii_case("local") {
        None
    } else {
        form.auth_provider_id
    };
    let is_active = parse_checkbox(&form.is_active);
    let password = form
        .password
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let password_hash: Option<String> = match (auth_mode.as_str(), password) {
        ("federated", _) => None,
        (_, Some(p)) => match simple_idm_core::auth::password::hash_password(p) {
            Ok(h) => Some(h),
            Err(e) => {
                return redirect_with(&return_path, "error", &format!("Password hash failed: {e}"))
                    .into_response();
            }
        },
        ("local", None) => {
            return redirect_with(
                &return_path,
                "error",
                "Password is required for local auth mode",
            )
            .into_response();
        }
        (_, None) => None,
    };
    let password_disabled = auth_mode.eq_ignore_ascii_case("federated");

    let result = sqlx::query(
        r#"INSERT INTO users (
             tenant_id, username, email, password_hash, is_active, auth_mode, auth_provider_id, password_disabled,
             first_name, last_name, recovery_email, phone_e164, note
           )
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
    )
    .bind(form.username.trim())
    .bind(&email)
    .bind(password_hash)
    .bind(is_active)
    .bind(auth_mode)
    .bind(auth_provider_id)
    .bind(password_disabled)
    .bind(&first_name)
    .bind(&last_name)
    .bind(&recovery_email)
    .bind(&phone_e164)
    .bind(&note)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(&return_path, "message", "User created").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Create failed: {e}")).into_response()
        }
    }
}

async fn users_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UserUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let email = form.email.trim().to_lowercase();
    if !looks_like_email(&email) {
        return redirect_with(&return_path, "error", "Invalid email format").into_response();
    }
    let recovery_email = normalize_opt_form(form.recovery_email).map(|v| v.to_lowercase());
    if let Some(value) = recovery_email.as_deref() {
        if !looks_like_email(value) {
            return redirect_with(&return_path, "error", "Invalid recovery email format")
                .into_response();
        }
    }
    let phone_e164 = normalize_opt_form(form.phone_e164);
    if let Some(value) = phone_e164.as_deref() {
        if !looks_like_e164(value) {
            return redirect_with(
                &return_path,
                "error",
                "Phone must use E.164 format, e.g. +420...",
            )
            .into_response();
        }
    }
    let first_name = normalize_opt_form(form.first_name);
    let last_name = normalize_opt_form(form.last_name);
    let note = normalize_opt_form(form.note);
    let auth_mode = normalize_auth_mode(form.auth_mode.as_deref());
    let auth_provider_id = if auth_mode.eq_ignore_ascii_case("local") {
        None
    } else {
        form.auth_provider_id
    };
    let is_active = parse_checkbox(&form.is_active);
    let password_disabled = auth_mode.eq_ignore_ascii_case("federated");

    let new_password = form
        .password
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let result = if auth_mode.eq_ignore_ascii_case("federated") {
        sqlx::query(
            r#"UPDATE users
               SET email = $2,
                   password_hash = NULL,
                   is_active = $3,
                   auth_mode = $4,
                   auth_provider_id = $5,
                   password_disabled = $6,
                   first_name = $7,
                   last_name = $8,
                   recovery_email = $9,
                   phone_e164 = $10,
                   note = $11,
                   updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(&email)
        .bind(is_active)
        .bind(auth_mode)
        .bind(auth_provider_id)
        .bind(password_disabled)
        .bind(&first_name)
        .bind(&last_name)
        .bind(&recovery_email)
        .bind(&phone_e164)
        .bind(&note)
        .execute(&state.db_pool)
        .await
    } else if let Some(password) = new_password {
        match simple_idm_core::auth::password::hash_password(password) {
            Ok(hash) => {
                sqlx::query(
                    r#"UPDATE users
                       SET email = $2,
                           password_hash = $3,
                           is_active = $4,
                           auth_mode = $5,
                           auth_provider_id = $6,
                           password_disabled = $7,
                           first_name = $8,
                           last_name = $9,
                           recovery_email = $10,
                           phone_e164 = $11,
                           note = $12,
                           updated_at = NOW()
                       WHERE id = $1"#,
                )
                .bind(id)
                .bind(&email)
                .bind(hash)
                .bind(is_active)
                .bind(auth_mode)
                .bind(auth_provider_id)
                .bind(password_disabled)
                .bind(&first_name)
                .bind(&last_name)
                .bind(&recovery_email)
                .bind(&phone_e164)
                .bind(&note)
                .execute(&state.db_pool)
                .await
            }
            Err(e) => {
                return redirect_with(&return_path, "error", &format!("Hash failed: {e}"))
                    .into_response();
            }
        }
    } else {
        sqlx::query(
            r#"UPDATE users
               SET email = $2,
                   is_active = $3,
                   auth_mode = $4,
                   auth_provider_id = $5,
                   password_disabled = $6,
                   first_name = $7,
                   last_name = $8,
                   recovery_email = $9,
                   phone_e164 = $10,
                   note = $11,
                   updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(&email)
        .bind(is_active)
        .bind(auth_mode)
        .bind(auth_provider_id)
        .bind(password_disabled)
        .bind(&first_name)
        .bind(&last_name)
        .bind(&recovery_email)
        .bind(&phone_e164)
        .bind(&note)
        .execute(&state.db_pool)
        .await
    };

    match result {
        Ok(_) => redirect_with(&return_path, "message", "User updated").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Update failed: {e}")).into_response()
        }
    }
}

async fn user_patterns_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    Form(form): Form<PatternCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = user_patterns_return_path_from_referer(&headers, user_id);
    if form.pattern.trim().is_empty() {
        return redirect_with(&return_path, "error", "Pattern is required").into_response();
    }

    match sqlx::query(
        r#"
        INSERT INTO user_group_patterns (tenant_id, user_id, pattern, is_include, priority)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(default_tenant_id())
    .bind(user_id)
    .bind(form.pattern.trim())
    .bind(pattern_mode_to_bool(&form.mode))
    .bind(pattern_priority(form.priority))
    .execute(&state.db_pool)
    .await
    {
        Ok(_) => redirect_with(&return_path, "message", "User pattern created").into_response(),
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Pattern create failed: {e}"),
        )
        .into_response(),
    }
}

async fn user_patterns_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path((user_id, pattern_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<PatternUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = user_patterns_return_path_from_referer(&headers, user_id);
    if form.pattern.trim().is_empty() {
        return redirect_with(&return_path, "error", "Pattern is required").into_response();
    }

    match sqlx::query(
        r#"
        UPDATE user_group_patterns
        SET pattern = $3, is_include = $4, priority = $5
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(pattern_id)
    .bind(user_id)
    .bind(form.pattern.trim())
    .bind(pattern_mode_to_bool(&form.mode))
    .bind(pattern_priority(form.priority))
    .execute(&state.db_pool)
    .await
    {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "User pattern updated").into_response()
        }
        Ok(_) => redirect_with(&return_path, "error", "User pattern not found").into_response(),
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Pattern update failed: {e}"),
        )
        .into_response(),
    }
}

async fn user_patterns_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path((user_id, pattern_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = user_patterns_return_path_from_referer(&headers, user_id);

    match sqlx::query(
        r#"
        UPDATE user_group_patterns
        SET deleted_at = NOW()
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(pattern_id)
    .bind(user_id)
    .execute(&state.db_pool)
    .await
    {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "User pattern deleted").into_response()
        }
        Ok(_) => redirect_with(&return_path, "error", "User pattern not found").into_response(),
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Pattern delete failed: {e}"),
        )
        .into_response(),
    }
}

async fn users_import_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    render_template(UsersImportTemplate {
        sections: nav_items(AdminSection::Users),
        message: query.message,
        error: query.error,
    })
}

async fn users_import_submit(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let mut note: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        let Some(name) = field.name().map(|s| s.to_string()) else {
            continue;
        };
        if name == "note" {
            note = field
                .text()
                .await
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
        } else if name == "file" {
            file_bytes = field.bytes().await.ok().map(|b| b.to_vec());
        }
    }

    let Some(bytes) = file_bytes else {
        return redirect_with("/admin/ui/users", "error", "Missing CSV file").into_response();
    };

    let imported = match parse_google_users_csv(&bytes) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => {
            return redirect_with("/admin/ui/users", "error", "CSV has no importable users")
                .into_response();
        }
        Err(e) => return redirect_with("/admin/ui/users", "error", &e).into_response(),
    };

    let mut created = 0usize;
    let mut updated = 0usize;
    let mut failed = 0usize;
    for item in imported {
        let existing = sqlx::query_scalar::<_, Uuid>(
            r#"SELECT id FROM users WHERE tenant_id = '11111111-1111-1111-1111-111111111111' AND email = $1 AND deleted_at IS NULL LIMIT 1"#,
        )
        .bind(&item.email)
        .fetch_optional(&state.db_pool)
        .await;

        let result = match existing {
            Ok(Some(user_id)) => sqlx::query(
                r#"UPDATE users
                       SET first_name = $2,
                           last_name = $3,
                           recovery_email = $4,
                           phone_e164 = $5,
                           last_sign_in_at = $6,
                           note = $7,
                           is_active = $8,
                           updated_at = NOW()
                       WHERE id = $1"#,
            )
            .bind(user_id)
            .bind(item.first_name.as_deref())
            .bind(item.last_name.as_deref())
            .bind(item.recovery_email.as_deref())
            .bind(item.phone.as_deref())
            .bind(item.last_sign_in_at)
            .bind(note.as_deref())
            .bind(item.is_active)
            .execute(&state.db_pool)
            .await
            .map(|_| {
                updated += 1;
            }),
            Ok(None) => {
                let generated_password = random_import_password();
                let password_hash =
                    match simple_idm_core::auth::password::hash_password(&generated_password) {
                        Ok(h) => h,
                        Err(_) => {
                            failed += 1;
                            continue;
                        }
                    };
                sqlx::query(
                    r#"INSERT INTO users (
                           tenant_id, username, email, password_hash, is_active,
                           first_name, last_name, recovery_email, phone_e164, last_sign_in_at, note
                       )
                       VALUES (
                           '11111111-1111-1111-1111-111111111111', $1, $2, $3, $4,
                           $5, $6, $7, $8, $9, $10
                       )"#,
                )
                .bind(username_from_email(&item.email))
                .bind(&item.email)
                .bind(password_hash)
                .bind(item.is_active)
                .bind(item.first_name.as_deref())
                .bind(item.last_name.as_deref())
                .bind(item.recovery_email.as_deref())
                .bind(item.phone.as_deref())
                .bind(item.last_sign_in_at)
                .bind(note.as_deref())
                .execute(&state.db_pool)
                .await
                .map(|_| {
                    created += 1;
                })
            }
            Err(e) => Err(e),
        };

        if result.is_err() {
            failed += 1;
        }
    }

    let msg = format!("Import completed: created={created}, updated={updated}, failed={failed}");
    redirect_with("/admin/ui/users", "message", &msg).into_response()
}

async fn users_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let result = sqlx::query(
        r#"UPDATE users
           SET is_active = false, deleted_at = NOW(), updated_at = NOW()
           WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            redirect_with(&return_path, "message", "User deactivated (safe delete)").into_response()
        }
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Deactivate failed: {e}")).into_response()
        }
    }
}

async fn users_mfa_reset(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    match simple_idm_core::mfa::admin_reset_user_mfa(&state.db_pool, id).await {
        Ok(true) => {
            simple_idm_core::audit::emit_event(
                &state.db_pool,
                "auth.mfa.admin_reset",
                "user",
                Some(id),
                "success",
                Some(json!({
                    "effect": "authenticators_revoked_recovery_codes_deleted_sessions_revoked"
                })),
            )
            .await;
            redirect_with(
                &return_path,
                "message",
                "MFA reset. Existing sessions were revoked; required MFA will enroll again at next login.",
            )
            .into_response()
        }
        Ok(false) => redirect_with(
            &return_path,
            "error",
            "MFA reset is available only for active local users",
        )
        .into_response(),
        Err(err) => {
            simple_idm_core::audit::emit_event(
                &state.db_pool,
                "auth.mfa.admin_reset",
                "user",
                Some(id),
                "failure",
                Some(json!({ "error": err.to_string() })),
            )
            .await;
            redirect_with(&return_path, "error", &format!("MFA reset failed: {err}"))
                .into_response()
        }
    }
}

async fn users_restore(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let result = sqlx::query(
        r#"UPDATE users
           SET deleted_at = NULL, updated_at = NOW()
           WHERE id = $1 AND deleted_at IS NOT NULL"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "User restored").into_response()
        }
        Ok(_) => {
            redirect_with(&return_path, "error", "User not found in deleted users").into_response()
        }
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Restore failed: {e}")).into_response()
        }
    }
}

async fn ad_onboarding_tokens_bulk_delete(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<AdTokenBulkDeleteForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let token_hashes = form
        .token_hashes_csv
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    if token_hashes.is_empty() {
        return redirect_with(&return_path, "error", "No onboarding token selected")
            .into_response();
    }

    let result = sqlx::query("DELETE FROM ad_onboarding_tokens WHERE token_hash = ANY($1)")
        .bind(&token_hashes)
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(done) => redirect_with(
            &return_path,
            "message",
            &format!("Deleted onboarding tokens: {}", done.rows_affected()),
        )
        .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Delete failed: {e}")).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct MappingDraftItem {
    mapping_id: Option<String>,
    external_role: String,
    group_id: String,
    priority: Option<i32>,
    mode: Option<String>,
}

async fn users_ad_mappings_apply(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UserAdMappingsApplyForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = users_return_path_from_referer(&headers);

    let user = match sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return redirect_with(&return_path, "error", "User not found").into_response(),
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };

    if user.auth_mode != "ad" {
        return redirect_with(
            &return_path,
            "error",
            "AD role mapping is available only for auth type 'ad'",
        )
        .into_response();
    }

    let items: Vec<MappingDraftItem> = match serde_json::from_str(form.mappings_json.trim()) {
        Ok(v) => v,
        Err(e) => {
            return redirect_with(
                &return_path,
                "error",
                &format!("Invalid mappings payload: {e}"),
            )
            .into_response();
        }
    };
    let Some(idp_id) = user.auth_provider_id else {
        return redirect_with(
            &return_path,
            "error",
            "AD user has no identity provider selected",
        )
        .into_response();
    };

    if items.is_empty() {
        return redirect_with(&return_path, "error", "No mappings selected").into_response();
    }

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };
    let mut changed = 0usize;
    for item in &items {
        let mode = item.mode.as_deref().unwrap_or("add");
        if mode == "deactivate" {
            let Some(mapping_id) = item.mapping_id.as_deref() else {
                continue;
            };
            let Ok(mapping_id) = Uuid::parse_str(mapping_id.trim()) else {
                continue;
            };
            let result = sqlx::query(
                r#"
                UPDATE external_role_mappings
                SET is_active = false, deleted_at = NOW(), updated_at = NOW()
                WHERE id = $1
                  AND tenant_id = $2
                  AND source = 'ad'
                  AND idp_id = $3
                  AND deleted_at IS NULL
                "#,
            )
            .bind(mapping_id)
            .bind(user.tenant_id)
            .bind(idp_id)
            .execute(&mut *tx)
            .await;
            if let Ok(done) = result {
                if done.rows_affected() > 0 {
                    changed += 1;
                }
            }
            continue;
        }

        let Ok(group_id) = Uuid::parse_str(item.group_id.trim()) else {
            continue;
        };
        let priority = item.priority.unwrap_or(100);
        if item.external_role.trim().is_empty() {
            continue;
        }
        let result = sqlx::query(
            r#"
            INSERT INTO external_role_mappings
              (tenant_id, source, external_role, group_id, mode, priority, is_active, idp_id)
            VALUES
              ($1, 'ad', $2, $3, 'add', $4, true, $5)
            ON CONFLICT (tenant_id, idp_id, source, external_role, group_id, mode)
            WHERE deleted_at IS NULL
            DO UPDATE SET
              is_active = true,
              priority = EXCLUDED.priority,
              updated_at = NOW()
            "#,
        )
        .bind(user.tenant_id)
        .bind(item.external_role.trim())
        .bind(group_id)
        .bind(priority)
        .bind(idp_id)
        .execute(&mut *tx)
        .await;
        if result.is_ok() {
            changed += 1;
        }
    }

    if let Err(e) = tx.commit().await {
        return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
    }

    if let Err(err) =
        oauth2::sync_ldap_roles_force(state.oauth_state.as_ref(), &user, &user.email).await
    {
        simple_idm_core::audit::emit_event(
            &state.db_pool,
            "ad.role_mapping.apply",
            "external_role_mappings",
            Some(user.id),
            "failure",
            Some(json!({"error": err.to_string()})),
        )
        .await;
        return redirect_with(
            &return_path,
            "error",
            &format!("Mappings saved ({changed}), but sync failed: {err}"),
        )
        .into_response();
    }

    simple_idm_core::audit::emit_event(
        &state.db_pool,
        "ad.role_mapping.apply",
        "external_role_mappings",
        Some(user.id),
        "success",
        Some(json!({"count": changed})),
    )
    .await;

    redirect_with(
        &return_path,
        "message",
        &format!("AD mappings applied: {changed}"),
    )
    .into_response()
}

async fn users_ad_onboarding_link(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let user =
        match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&state.db_pool)
            .await
        {
            Ok(Some(v)) => v,
            Ok(None) => {
                return redirect_with(&return_path, "error", "User not found").into_response();
            }
            Err(e) => {
                return redirect_with(&return_path, "error", &format!("DB error: {e}"))
                    .into_response();
            }
        };
    if !user.auth_mode.eq_ignore_ascii_case("ad") {
        return redirect_with(
            &return_path,
            "error",
            "AD onboarding is available only for auth type 'ad'",
        )
        .into_response();
    }
    let Some(idp_id) = user.auth_provider_id else {
        return redirect_with(
            &return_path,
            "error",
            "AD user has no identity provider selected",
        )
        .into_response();
    };
    if let Err(e) = oauth2::load_ad_ldap_provider(&state.db_pool, idp_id).await {
        return redirect_with(&return_path, "error", &format!("AD provider error: {e}"))
            .into_response();
    }

    let raw_token = random_onboarding_token();
    let token_hash = onboarding_token_hash(&raw_token);
    let expires_at = Utc::now() + chrono::Duration::seconds(state.ad_onboarding_token_ttl_seconds);

    let result = sqlx::query(
        r#"
        INSERT INTO ad_onboarding_tokens (user_id, token_hash, expires_at, idp_id)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(idp_id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            let link = public_url_from_headers(
                &headers,
                &format!("/ad/onboarding?token={}", urlencoding::encode(&raw_token)),
            );
            let msg = format!(
                "AD onboarding link generated ({}h)",
                state.ad_onboarding_token_ttl_seconds / 3600
            );
            simple_idm_core::audit::emit_event(
                &state.db_pool,
                "ad.onboarding.link.create",
                "ad_onboarding",
                Some(id),
                "success",
                Some(serde_json::json!({"expires_at": expires_at.to_rfc3339()})),
            )
            .await;
            Redirect::to(&format!(
                "{}{}message={}&ad_link={}",
                return_path,
                if return_path.contains('?') { "&" } else { "?" },
                urlencoding::encode(&msg),
                urlencoding::encode(&link)
            ))
            .into_response()
        }
        Err(e) => {
            simple_idm_core::audit::emit_event(
                &state.db_pool,
                "ad.onboarding.link.create",
                "ad_onboarding",
                Some(id),
                "failure",
                Some(serde_json::json!({"error": e.to_string()})),
            )
            .await;
            redirect_with(
                &return_path,
                "error",
                &format!("Failed to generate onboarding link: {e}"),
            )
            .into_response()
        }
    }
}

async fn users_federated_invitation_link(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<FederatedInvitationForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let user = match sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return redirect_with(&return_path, "error", "User not found").into_response(),
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };

    if !user.auth_mode.eq_ignore_ascii_case("federated") {
        return redirect_with(
            &return_path,
            "error",
            "Federated invitation is available only for auth type 'federated'",
        )
        .into_response();
    }

    let providers = match sqlx::query_as::<_, (Uuid, String, String)>(
        r#"
        SELECT id, slug, provider_type
        FROM identity_providers
        WHERE tenant_id = $1
          AND is_active = true
          AND provider_type <> 'ad_ldap'
          AND deleted_at IS NULL
        ORDER BY slug ASC
        "#,
    )
    .bind(user.tenant_id)
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };

    let requested_idp_id = form.idp_id.or(user.auth_provider_id);
    let selected_provider = if let Some(idp_id) = requested_idp_id {
        providers
            .into_iter()
            .find(|(provider_id, _, _)| *provider_id == idp_id)
    } else if providers.len() == 1 {
        providers.into_iter().next()
    } else {
        None
    };

    let Some((idp_id, provider_slug, provider_type)) = selected_provider else {
        return redirect_with(
            &return_path,
            "error",
            "Set an active federated identity provider in Edit user first",
        )
        .into_response();
    };

    let raw_token = random_onboarding_token();
    let token_hash = onboarding_token_hash(&raw_token);
    let expires_at =
        Utc::now() + chrono::Duration::seconds(state.federated_invitation_token_ttl_seconds);

    let result = sqlx::query(
        r#"
        INSERT INTO federated_invitation_tokens (user_id, idp_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(id)
    .bind(idp_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            let link = public_url_from_headers(
                &headers,
                &format!(
                    "/federated/onboarding?token={}",
                    urlencoding::encode(&raw_token)
                ),
            );
            let msg = format!(
                "Federated invitation generated via {} ({})",
                provider_slug, provider_type
            );
            simple_idm_core::audit::emit_event(
                &state.db_pool,
                "federated.invitation.create",
                "federated_invitation_tokens",
                Some(id),
                "success",
                Some(json!({
                    "provider": provider_slug,
                    "provider_type": provider_type,
                    "expires_at": expires_at.to_rfc3339()
                })),
            )
            .await;
            Redirect::to(&format!(
                "{}{}message={}&federated_link={}",
                return_path,
                if return_path.contains('?') { "&" } else { "?" },
                urlencoding::encode(&msg),
                urlencoding::encode(&link)
            ))
            .into_response()
        }
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Failed to generate federated invitation: {e}"),
        )
        .into_response(),
    }
}

async fn users_federated_approve(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let result = sqlx::query(
        r#"
        UPDATE user_identities
        SET approval_status = 'approved',
            approved_at = NOW(),
            rejected_at = NULL,
            updated_at = NOW()
        WHERE user_id = $1
          AND deleted_at IS NULL
          AND approval_status = 'pending'
        "#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            simple_idm_core::audit::emit_event(
                &state.db_pool,
                "federated.identity.approve",
                "user_identities",
                Some(id),
                "success",
                Some(json!({"approved_rows": done.rows_affected()})),
            )
            .await;
            redirect_with(&return_path, "message", "Federated identity approved").into_response()
        }
        Ok(_) => redirect_with(&return_path, "error", "No pending federated identity found")
            .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Approve failed: {e}")).into_response()
        }
    }
}

async fn users_federated_unlink(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = users_return_path_from_referer(&headers);
    let result = sqlx::query(
        r#"
        UPDATE user_identities
        SET deleted_at = NOW(),
            updated_at = NOW()
        WHERE user_id = $1
          AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            simple_idm_core::audit::emit_event(
                &state.db_pool,
                "federated.identity.unlink",
                "user_identities",
                Some(id),
                "success",
                Some(json!({"rows": done.rows_affected()})),
            )
            .await;
            redirect_with(&return_path, "message", "Federated identity unlinked").into_response()
        }
        Ok(_) => {
            redirect_with(&return_path, "error", "No federated identity to unlink").into_response()
        }
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Failed to unlink federated identity: {e}"),
        )
        .into_response(),
    }
}

async fn groups_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, GroupRow>(
        r#"SELECT id, name, description, is_virtual FROM groups WHERE deleted_at IS NULL ORDER BY name ASC"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/groups", "error", &format!("DB error: {e}")).into_response();
        }
    };

    let relations = sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT parent_group_id, child_group_id FROM group_groups ORDER BY parent_group_id, child_group_id",
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();
    let tree_rows = build_group_tree_rows(&rows, &relations);
    let deleted_rows = sqlx::query_as::<_, GroupRow>(
        r#"SELECT id, name, description, is_virtual FROM groups WHERE deleted_at IS NOT NULL ORDER BY updated_at DESC, name ASC LIMIT 25"#,
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    render_template(GroupsTemplate {
        sections: nav_items(AdminSection::Groups),
        message: query.message,
        error: query.error,
        tree_rows,
        deleted_rows,
    })
}

async fn groups_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<GroupCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result =
        sqlx::query(r#"INSERT INTO groups (name, description, is_virtual) VALUES ($1, $2, $3)"#)
            .bind(form.name.trim())
            .bind(Some(form.description.trim()).filter(|v| !v.is_empty()))
            .bind(parse_checkbox(&form.is_virtual))
            .execute(&state.db_pool)
            .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/groups", "message", "Group created").into_response(),
        Err(e) => redirect_with("/admin/ui/groups", "error", &format!("Create failed: {e}"))
            .into_response(),
    }
}

async fn groups_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<GroupUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result =
        sqlx::query(r#"UPDATE groups SET name=$2, description=$3, is_virtual=$4 WHERE id=$1"#)
            .bind(id)
            .bind(form.name.trim())
            .bind(Some(form.description.trim()).filter(|v| !v.is_empty()))
            .bind(parse_checkbox(&form.is_virtual))
            .execute(&state.db_pool)
            .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/groups", "message", "Group updated").into_response(),
        Err(e) => redirect_with("/admin/ui/groups", "error", &format!("Update failed: {e}"))
            .into_response(),
    }
}

async fn groups_reparent(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<GroupReparentForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let new_parent = match parse_parent_group_id(form.parent_group_id.as_deref()) {
        Ok(v) => v,
        Err(e) => return redirect_with("/admin/ui/groups", "error", &e).into_response(),
    };

    if let Some(parent_id) = new_parent {
        if parent_id == id {
            return redirect_with(
                "/admin/ui/groups",
                "error",
                "Group cannot be its own parent",
            )
            .into_response();
        }
        match would_create_group_cycle(&state.db_pool, parent_id, id).await {
            Ok(true) => {
                return redirect_with(
                    "/admin/ui/groups",
                    "error",
                    "Selected parent would create a cycle",
                )
                .into_response();
            }
            Err(e) => {
                return redirect_with("/admin/ui/groups", "error", &format!("DB error: {e}"))
                    .into_response();
            }
            Ok(false) => {}
        }
    }

    let mut tx = match state.db_pool.begin().await {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/groups", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    if let Err(e) = sqlx::query("DELETE FROM group_groups WHERE child_group_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
    {
        return redirect_with(
            "/admin/ui/groups",
            "error",
            &format!("Reparent failed: {e}"),
        )
        .into_response();
    }

    if let Some(parent_id) = new_parent {
        if let Err(e) = sqlx::query(
            "INSERT INTO group_groups (parent_group_id, child_group_id) VALUES ($1, $2)",
        )
        .bind(parent_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        {
            return redirect_with(
                "/admin/ui/groups",
                "error",
                &format!("Reparent failed: {e}"),
            )
            .into_response();
        }
    }

    match tx.commit().await {
        Ok(_) => redirect_with("/admin/ui/groups", "message", "Group moved").into_response(),
        Err(e) => redirect_with(
            "/admin/ui/groups",
            "error",
            &format!("Reparent failed: {e}"),
        )
        .into_response(),
    }
}

async fn groups_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result =
        sqlx::query(r#"UPDATE groups SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1"#)
            .bind(id)
            .execute(&state.db_pool)
            .await;

    match result {
        Ok(_) => redirect_with(
            "/admin/ui/groups",
            "message",
            "Group deactivated (safe delete)",
        )
        .into_response(),
        Err(e) => redirect_with(
            "/admin/ui/groups",
            "error",
            &format!("Deactivate failed: {e}"),
        )
        .into_response(),
    }
}

async fn groups_restore(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(
        r#"UPDATE groups SET deleted_at = NULL, updated_at = NOW() WHERE id = $1 AND deleted_at IS NOT NULL"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with("/admin/ui/groups", "message", "Group restored").into_response()
        }
        Ok(_) => redirect_with("/admin/ui/groups", "error", "Group is not deleted").into_response(),
        Err(e) => redirect_with("/admin/ui/groups", "error", &format!("Restore failed: {e}"))
            .into_response(),
    }
}

async fn tenants_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let tenants = match sqlx::query_as::<_, TenantRow>(
        r#"
        SELECT
            t.id,
            t.slug,
            t.name,
            t.mode::text AS mode,
            t.is_active,
            t.mfa_policy,
            (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id AND u.deleted_at IS NULL) AS users_count,
            (SELECT COUNT(*) FROM groups g WHERE g.tenant_id = t.id AND g.deleted_at IS NULL) AS groups_count,
            (SELECT COUNT(*) FROM oauth_clients oc WHERE oc.tenant_id = t.id AND oc.deleted_at IS NULL) AS clients_count,
            (SELECT COUNT(*) FROM tenant_domains td WHERE td.tenant_id = t.id AND td.deleted_at IS NULL) AS domains_count
        FROM tenants t
        WHERE t.deleted_at IS NULL
        ORDER BY t.slug ASC
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/", "error", &format!("DB error: {e}")).into_response();
        }
    };

    let domains = sqlx::query_as::<_, TenantDomainRow>(
        r#"
        SELECT
            td.id,
            t.slug AS tenant_slug,
            t.name AS tenant_name,
            td.domain,
            td.is_primary,
            td.is_active
        FROM tenant_domains td
        JOIN tenants t ON t.id = td.tenant_id
        WHERE td.deleted_at IS NULL
        ORDER BY td.is_primary DESC, td.domain ASC
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let deleted_domains = sqlx::query_as::<_, TenantDomainRow>(
        r#"
        SELECT
            td.id,
            t.slug AS tenant_slug,
            t.name AS tenant_name,
            td.domain,
            td.is_primary,
            td.is_active
        FROM tenant_domains td
        JOIN tenants t ON t.id = td.tenant_id
        WHERE td.deleted_at IS NOT NULL
        ORDER BY td.deleted_at DESC, td.domain ASC
        LIMIT 25
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    render_template(TenantsTemplate {
        sections: nav_items(AdminSection::Tenants),
        message: query.message,
        error: query.error,
        tenants,
        domains,
        deleted_domains,
    })
}

async fn tenants_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<TenantUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let mode = form.mode.trim();
    if mode != "single" && mode != "multi" {
        return redirect_with("/admin/ui/tenants", "error", "Invalid tenant mode").into_response();
    }

    let name = form.name.trim();
    if name.is_empty() {
        return redirect_with("/admin/ui/tenants", "error", "Tenant name is required")
            .into_response();
    }

    let mfa_policy = form.mfa_policy.trim();
    if !matches!(mfa_policy, "disabled" | "optional" | "required") {
        return redirect_with("/admin/ui/tenants", "error", "Invalid MFA policy").into_response();
    }

    let result = sqlx::query(
        r#"
        UPDATE tenants
        SET name = $2,
            mode = $3::tenant_mode,
            mfa_policy = $4,
            is_active = $5,
            updated_at = NOW()
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(mode)
    .bind(mfa_policy)
    .bind(parse_checkbox(&form.is_active))
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with("/admin/ui/tenants", "message", "Tenant updated").into_response()
        }
        Ok(_) => redirect_with("/admin/ui/tenants", "error", "Tenant not found").into_response(),
        Err(e) => redirect_with("/admin/ui/tenants", "error", &format!("Update failed: {e}"))
            .into_response(),
    }
}

async fn tenant_domains_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<TenantDomainCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let domain = match normalize_domain(&form.domain) {
        Ok(v) => v,
        Err(e) => return redirect_with("/admin/ui/tenants", "error", &e).into_response(),
    };
    let is_primary = parse_checkbox(&form.is_primary);

    if is_primary {
        if let Err(e) =
            sqlx::query("UPDATE tenant_domains SET is_primary = false WHERE tenant_id = $1")
                .bind(form.tenant_id)
                .execute(&state.db_pool)
                .await
        {
            return redirect_with(
                "/admin/ui/tenants",
                "error",
                &format!("Primary update failed: {e}"),
            )
            .into_response();
        }
    }

    let result = sqlx::query(
        r#"
        INSERT INTO tenant_domains (tenant_id, domain, is_primary, is_active)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(form.tenant_id)
    .bind(domain)
    .bind(is_primary)
    .bind(parse_checkbox(&form.is_active))
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/tenants", "message", "Domain added").into_response(),
        Err(e) => redirect_with("/admin/ui/tenants", "error", &format!("Create failed: {e}"))
            .into_response(),
    }
}

async fn tenant_domains_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<TenantDomainUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let domain = match normalize_domain(&form.domain) {
        Ok(v) => v,
        Err(e) => return redirect_with("/admin/ui/tenants", "error", &e).into_response(),
    };
    let is_primary = parse_checkbox(&form.is_primary);
    let tenant_id = match sqlx::query_scalar::<_, Uuid>(
        "SELECT tenant_id FROM tenant_domains WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return redirect_with("/admin/ui/tenants", "error", "Domain not found").into_response();
        }
        Err(e) => {
            return redirect_with("/admin/ui/tenants", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    if is_primary {
        if let Err(e) =
            sqlx::query("UPDATE tenant_domains SET is_primary = false WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&state.db_pool)
                .await
        {
            return redirect_with(
                "/admin/ui/tenants",
                "error",
                &format!("Primary update failed: {e}"),
            )
            .into_response();
        }
    }

    let result = sqlx::query(
        r#"
        UPDATE tenant_domains
        SET domain = $2,
            is_primary = $3,
            is_active = $4
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .bind(domain)
    .bind(is_primary)
    .bind(parse_checkbox(&form.is_active))
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with("/admin/ui/tenants", "message", "Domain updated").into_response()
        }
        Ok(_) => redirect_with("/admin/ui/tenants", "error", "Domain not found").into_response(),
        Err(e) => redirect_with("/admin/ui/tenants", "error", &format!("Update failed: {e}"))
            .into_response(),
    }
}

async fn tenant_domains_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(
        "UPDATE tenant_domains SET deleted_at = NOW(), is_active = false WHERE id = $1",
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            redirect_with("/admin/ui/tenants", "message", "Domain deactivated").into_response()
        }
        Err(e) => redirect_with(
            "/admin/ui/tenants",
            "error",
            &format!("Deactivate failed: {e}"),
        )
        .into_response(),
    }
}

async fn tenant_domains_restore(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(
        "UPDATE tenant_domains SET deleted_at = NULL, is_active = true WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with("/admin/ui/tenants", "message", "Domain restored").into_response()
        }
        Ok(_) => {
            redirect_with("/admin/ui/tenants", "error", "Domain is not deleted").into_response()
        }
        Err(e) => redirect_with(
            "/admin/ui/tenants",
            "error",
            &format!("Restore failed: {e}"),
        )
        .into_response(),
    }
}

async fn identity_providers_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let filter_q = query.q.unwrap_or_default();
    let search_patterns = filter_q
        .split_whitespace()
        .map(|term| format!("%{}%", term.to_lowercase()))
        .collect::<Vec<_>>();

    let rows = match sqlx::query_as::<_, IdentityProviderRow>(
        r#"
        SELECT
          ip.id, ip.slug, ip.provider_type, ip.issuer, ip.client_id, ip.auth_url, ip.token_url, ip.jwks_url, ip.scopes, ip.hd_domain, ip.is_active,
          ad.host AS ad_host,
          ad.port AS ad_port,
          ad.base_dn AS ad_base_dn,
          ad.user_filter AS ad_user_filter,
          ad.tls_mode AS ad_tls_mode,
          ad.timeout_seconds AS ad_timeout_seconds,
          ad.allow_insecure AS ad_allow_insecure,
          ad.domains AS ad_domains,
          ad.bind_dn AS ad_bind_dn,
          ad.role_sync_enabled AS ad_role_sync_enabled,
          ad.role_sync_ttl_seconds AS ad_role_sync_ttl_seconds,
          ad.role_sync_timeout_seconds AS ad_role_sync_timeout_seconds
        FROM identity_providers ip
        LEFT JOIN identity_provider_ad_ldap_configs ad ON ad.idp_id = ip.id
        WHERE ip.tenant_id = $1 AND ip.deleted_at IS NULL
          AND (
            cardinality($2::text[]) = 0 OR
            lower(concat_ws(' ', ip.slug, ip.provider_type, ip.issuer, ip.client_id, COALESCE(ip.hd_domain, ''), COALESCE(ad.host, ''), COALESCE(array_to_string(ad.domains, ' '), ''))) LIKE ALL($2::text[])
          )
        ORDER BY ip.slug ASC
        "#,
    )
    .bind(default_tenant_id())
    .bind(&search_patterns)
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with(
                "/admin/ui/identity-providers",
                "error",
                &format!("DB error: {e}"),
            )
            .into_response();
        }
    };

    let deleted_rows = sqlx::query_as::<_, IdentityProviderRow>(
        r#"
        SELECT
          ip.id, ip.slug, ip.provider_type, ip.issuer, ip.client_id, ip.auth_url, ip.token_url, ip.jwks_url, ip.scopes, ip.hd_domain, ip.is_active,
          ad.host AS ad_host,
          ad.port AS ad_port,
          ad.base_dn AS ad_base_dn,
          ad.user_filter AS ad_user_filter,
          ad.tls_mode AS ad_tls_mode,
          ad.timeout_seconds AS ad_timeout_seconds,
          ad.allow_insecure AS ad_allow_insecure,
          ad.domains AS ad_domains,
          ad.bind_dn AS ad_bind_dn,
          ad.role_sync_enabled AS ad_role_sync_enabled,
          ad.role_sync_ttl_seconds AS ad_role_sync_ttl_seconds,
          ad.role_sync_timeout_seconds AS ad_role_sync_timeout_seconds
        FROM identity_providers ip
        LEFT JOIN identity_provider_ad_ldap_configs ad ON ad.idp_id = ip.id
        WHERE ip.tenant_id = $1 AND ip.deleted_at IS NOT NULL
        ORDER BY ip.deleted_at DESC
        LIMIT 50
        "#,
    )
    .bind(default_tenant_id())
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    render_template(IdentityProvidersTemplate {
        sections: nav_items(AdminSection::IdentityProviders),
        message: query.message,
        error: query.error,
        rows,
        deleted_rows,
        filter_q,
    })
}

async fn identity_providers_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<IdentityProviderCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = q_return_path_from_referer(
        &headers,
        "/admin/ui/identity-providers",
        "/admin/ui/identity-providers",
    );

    let scopes =
        selected_oidc_provider_scopes(&form.scope_openid, &form.scope_profile, &form.scope_email);
    let provider_type = normalize_provider_type(&form.provider_type);
    let is_ad_ldap = provider_type == "ad_ldap";
    if is_ad_ldap
        && form
            .ad_host
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none()
    {
        return redirect_with(&return_path, "error", "AD host is required").into_response();
    }
    if is_ad_ldap
        && form
            .ad_base_dn
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none()
    {
        return redirect_with(&return_path, "error", "AD base DN is required").into_response();
    }
    if !is_ad_ldap
        && (form.issuer.trim().is_empty()
            || form.client_id.trim().is_empty()
            || form.client_secret.trim().is_empty())
    {
        return redirect_with(
            &return_path,
            "error",
            "Issuer, client ID and client secret are required for OIDC providers",
        )
        .into_response();
    }

    let encrypted_secret = if is_ad_ldap {
        String::new()
    } else {
        match encrypt_secret(form.client_secret.trim()) {
            Ok(v) => v,
            Err(e) => {
                return redirect_with(
                    &return_path,
                    "error",
                    &format!("Secret encryption failed: {e}"),
                )
                .into_response();
            }
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(v) => v,
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };

    let result = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO identity_providers (
            tenant_id, slug, provider_type, issuer, client_id, client_secret_encrypted,
            auth_url, token_url, jwks_url, scopes, hd_domain, is_active
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id
        "#,
    )
    .bind(default_tenant_id())
    .bind(form.slug.trim())
    .bind(&provider_type)
    .bind(if is_ad_ldap {
        format!("ad_ldap:{}", form.slug.trim())
    } else {
        form.issuer.trim().to_string()
    })
    .bind(if is_ad_ldap {
        form.slug.trim()
    } else {
        form.client_id.trim()
    })
    .bind(encrypted_secret)
    .bind(if is_ad_ldap {
        None
    } else {
        form.auth_url
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
    })
    .bind(if is_ad_ldap {
        None
    } else {
        form.token_url
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
    })
    .bind(if is_ad_ldap {
        None
    } else {
        form.jwks_url
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
    })
    .bind(if is_ad_ldap {
        Vec::<String>::new()
    } else {
        scopes
    })
    .bind(if is_ad_ldap {
        None
    } else {
        form.hd_domain
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_lowercase)
    })
    .bind(parse_checkbox(&form.is_active))
    .fetch_one(&mut *tx)
    .await;

    match result {
        Ok(idp_id) => {
            if is_ad_ldap {
                let encrypted_bind_password = match form
                    .ad_bind_password
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                {
                    Some(secret) => match encrypt_secret(secret) {
                        Ok(v) => Some(v),
                        Err(e) => {
                            return redirect_with(
                                &return_path,
                                "error",
                                &format!("Bind password encryption failed: {e}"),
                            )
                            .into_response();
                        }
                    },
                    None => None,
                };
                if let Err(e) = sqlx::query(
                    r#"
                    INSERT INTO identity_provider_ad_ldap_configs (
                      idp_id, host, port, base_dn, user_filter, tls_mode, timeout_seconds,
                      allow_insecure, bind_dn, bind_password_encrypted, domains,
                      role_sync_enabled, role_sync_ttl_seconds, role_sync_timeout_seconds
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    "#,
                )
                .bind(idp_id)
                .bind(form.ad_host.as_deref().map(str::trim).unwrap_or(""))
                .bind(form.ad_port.unwrap_or(636))
                .bind(form.ad_base_dn.as_deref().map(str::trim).unwrap_or(""))
                .bind(
                    form.ad_user_filter
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .unwrap_or(
                            "(|(mail={login})(sAMAccountName={login})(userPrincipalName={login}))",
                        ),
                )
                .bind(
                    form.ad_tls_mode
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .unwrap_or("ldaps"),
                )
                .bind(form.ad_timeout_seconds.unwrap_or(5))
                .bind(parse_checkbox(&form.ad_allow_insecure))
                .bind(
                    form.ad_bind_dn
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty()),
                )
                .bind(encrypted_bind_password)
                .bind(csv_to_vec(form.ad_domains.as_deref()))
                .bind(parse_checkbox(&form.ad_role_sync_enabled))
                .bind(form.ad_role_sync_ttl_seconds.unwrap_or(3600))
                .bind(form.ad_role_sync_timeout_seconds.unwrap_or(5))
                .execute(&mut *tx)
                .await
                {
                    return redirect_with(
                        &return_path,
                        "error",
                        &format!("AD LDAP config create failed: {e}"),
                    )
                    .into_response();
                }
            }
            if let Err(e) = tx.commit().await {
                return redirect_with(&return_path, "error", &format!("DB error: {e}"))
                    .into_response();
            }
            redirect_with(&return_path, "message", "Identity provider created").into_response()
        }
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Create failed: {e}")).into_response()
        }
    }
}

async fn identity_providers_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<IdentityProviderUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = q_return_path_from_referer(
        &headers,
        "/admin/ui/identity-providers",
        "/admin/ui/identity-providers",
    );

    let scopes =
        selected_oidc_provider_scopes(&form.scope_openid, &form.scope_profile, &form.scope_email);
    let provider_type = normalize_provider_type(&form.provider_type);
    let is_ad_ldap = provider_type == "ad_ldap";
    if is_ad_ldap
        && form
            .ad_host
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none()
    {
        return redirect_with(&return_path, "error", "AD host is required").into_response();
    }
    if is_ad_ldap
        && form
            .ad_base_dn
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none()
    {
        return redirect_with(&return_path, "error", "AD base DN is required").into_response();
    }
    if !is_ad_ldap && (form.issuer.trim().is_empty() || form.client_id.trim().is_empty()) {
        return redirect_with(
            &return_path,
            "error",
            "Issuer and client ID are required for OIDC providers",
        )
        .into_response();
    }
    let encrypted_secret_update = match form
        .client_secret
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(secret) => match encrypt_secret(secret) {
            Ok(v) => Some(v),
            Err(e) => {
                return redirect_with(
                    &return_path,
                    "error",
                    &format!("Secret encryption failed: {e}"),
                )
                .into_response();
            }
        },
        None => None,
    };
    let encrypted_bind_password_update = match form
        .ad_bind_password
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(secret) => match encrypt_secret(secret) {
            Ok(v) => Some(v),
            Err(e) => {
                return redirect_with(
                    &return_path,
                    "error",
                    &format!("Bind password encryption failed: {e}"),
                )
                .into_response();
            }
        },
        None => None,
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(v) => v,
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };

    let result = sqlx::query(
        r#"
        UPDATE identity_providers
        SET slug = $2,
            provider_type = $3,
            issuer = $4,
            client_id = $5,
            client_secret_encrypted = COALESCE($6, client_secret_encrypted),
            auth_url = $7,
            token_url = $8,
            jwks_url = $9,
            scopes = $10,
            hd_domain = $11,
            is_active = $12,
            updated_at = NOW()
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .bind(form.slug.trim())
    .bind(&provider_type)
    .bind(if is_ad_ldap {
        format!("ad_ldap:{}", form.slug.trim())
    } else {
        form.issuer.trim().to_string()
    })
    .bind(if is_ad_ldap {
        form.slug.trim()
    } else {
        form.client_id.trim()
    })
    .bind(encrypted_secret_update)
    .bind(if is_ad_ldap {
        None
    } else {
        form.auth_url
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
    })
    .bind(if is_ad_ldap {
        None
    } else {
        form.token_url
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
    })
    .bind(if is_ad_ldap {
        None
    } else {
        form.jwks_url
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
    })
    .bind(if is_ad_ldap {
        Vec::<String>::new()
    } else {
        scopes
    })
    .bind(if is_ad_ldap {
        None
    } else {
        form.hd_domain
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_lowercase)
    })
    .bind(parse_checkbox(&form.is_active))
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            if is_ad_ldap {
                if let Err(e) = sqlx::query(
                    r#"
                    INSERT INTO identity_provider_ad_ldap_configs (
                      idp_id, host, port, base_dn, user_filter, tls_mode, timeout_seconds,
                      allow_insecure, bind_dn, bind_password_encrypted, domains,
                      role_sync_enabled, role_sync_ttl_seconds, role_sync_timeout_seconds
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    ON CONFLICT (idp_id)
                    DO UPDATE SET
                      host = EXCLUDED.host,
                      port = EXCLUDED.port,
                      base_dn = EXCLUDED.base_dn,
                      user_filter = EXCLUDED.user_filter,
                      tls_mode = EXCLUDED.tls_mode,
                      timeout_seconds = EXCLUDED.timeout_seconds,
                      allow_insecure = EXCLUDED.allow_insecure,
                      bind_dn = EXCLUDED.bind_dn,
                      bind_password_encrypted = COALESCE(EXCLUDED.bind_password_encrypted, identity_provider_ad_ldap_configs.bind_password_encrypted),
                      domains = EXCLUDED.domains,
                      role_sync_enabled = EXCLUDED.role_sync_enabled,
                      role_sync_ttl_seconds = EXCLUDED.role_sync_ttl_seconds,
                      role_sync_timeout_seconds = EXCLUDED.role_sync_timeout_seconds,
                      updated_at = NOW()
                    "#,
                )
                .bind(id)
                .bind(form.ad_host.as_deref().map(str::trim).unwrap_or(""))
                .bind(form.ad_port.unwrap_or(636))
                .bind(form.ad_base_dn.as_deref().map(str::trim).unwrap_or(""))
                .bind(form.ad_user_filter.as_deref().map(str::trim).filter(|v| !v.is_empty()).unwrap_or("(|(mail={login})(sAMAccountName={login})(userPrincipalName={login}))"))
                .bind(form.ad_tls_mode.as_deref().map(str::trim).filter(|v| !v.is_empty()).unwrap_or("ldaps"))
                .bind(form.ad_timeout_seconds.unwrap_or(5))
                .bind(parse_checkbox(&form.ad_allow_insecure))
                .bind(form.ad_bind_dn.as_deref().map(str::trim).filter(|v| !v.is_empty()))
                .bind(encrypted_bind_password_update)
                .bind(csv_to_vec(form.ad_domains.as_deref()))
                .bind(parse_checkbox(&form.ad_role_sync_enabled))
                .bind(form.ad_role_sync_ttl_seconds.unwrap_or(3600))
                .bind(form.ad_role_sync_timeout_seconds.unwrap_or(5))
                .execute(&mut *tx)
                .await {
                    return redirect_with(&return_path, "error", &format!("AD LDAP config update failed: {e}")).into_response();
                }
            }
            if let Err(e) = tx.commit().await {
                return redirect_with(&return_path, "error", &format!("DB error: {e}"))
                    .into_response();
            }
            redirect_with(&return_path, "message", "Identity provider updated").into_response()
        }
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Update failed: {e}")).into_response()
        }
    }
}

async fn identity_providers_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = q_return_path_from_referer(
        &headers,
        "/admin/ui/identity-providers",
        "/admin/ui/identity-providers",
    );

    let result = sqlx::query(
        r#"UPDATE identity_providers SET is_active = false, deleted_at = NOW(), updated_at = NOW() WHERE id = $1"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(
            &return_path,
            "message",
            "Identity provider deactivated (safe delete)",
        )
        .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Deactivate failed: {e}")).into_response()
        }
    }
}

async fn identity_providers_restore(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = q_return_path_from_referer(
        &headers,
        "/admin/ui/identity-providers",
        "/admin/ui/identity-providers",
    );

    let result = sqlx::query(
        r#"
        UPDATE identity_providers
        SET deleted_at = NULL, updated_at = NOW()
        WHERE id = $1 AND deleted_at IS NOT NULL
        "#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "Identity provider restored").into_response()
        }
        Ok(_) => redirect_with(
            &return_path,
            "error",
            "Identity provider not found in deleted providers",
        )
        .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Restore failed: {e}")).into_response()
        }
    }
}

async fn memberships_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<MembershipsQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let users = match sqlx::query_as::<_, MembershipUserRecord>(
        r#"SELECT id, username, email, first_name, last_name, auth_mode::text AS auth_mode, is_active
           FROM users
           WHERE tenant_id = $1 AND deleted_at IS NULL
           ORDER BY lower(username), lower(email)"#,
    )
    .bind(default_tenant_id())
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/memberships", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let groups = match sqlx::query_as::<_, MembershipGroupRecord>(
        r#"SELECT id, name, description, is_virtual
           FROM groups
           WHERE tenant_id = $1 AND deleted_at IS NULL
           ORDER BY lower(name)"#,
    )
    .bind(default_tenant_id())
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/memberships", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let selected_user_id = query.user_id.or_else(|| users.first().map(|u| u.id));
    let selected_group_id = query.group_id.or_else(|| groups.first().map(|g| g.id));

    let rows = match sqlx::query_as::<_, UserGroupRow>(
        r#"SELECT u.id AS user_id,
                  u.username,
                  u.email,
                  u.first_name,
                  u.last_name,
                  u.auth_mode::text AS auth_mode,
                  u.is_active,
                  g.id AS group_id,
                  g.name AS group_name,
                  g.description AS group_description,
                  g.is_virtual AS group_is_virtual
           FROM user_groups ug
           JOIN users u ON u.id = ug.user_id
           JOIN groups g ON g.id = ug.group_id
           WHERE ug.tenant_id = $1
             AND u.deleted_at IS NULL
             AND g.deleted_at IS NULL
           ORDER BY lower(u.username), lower(g.name)"#,
    )
    .bind(default_tenant_id())
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/memberships", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let users = users
        .into_iter()
        .map(|u| MembershipUserOption {
            selected: Some(u.id) == selected_user_id,
            id: u.id,
            username: u.username,
            email: u.email,
            first_name: u.first_name,
            last_name: u.last_name,
            auth_mode: u.auth_mode,
            is_active: u.is_active,
        })
        .collect::<Vec<_>>();

    let groups = groups
        .into_iter()
        .map(|g| MembershipGroupOption {
            selected: Some(g.id) == selected_group_id,
            id: g.id,
            name: g.name,
            description: g.description,
            is_virtual: g.is_virtual,
        })
        .collect::<Vec<_>>();

    let selected_user = users.iter().find(|u| u.selected).cloned();
    let selected_group = groups.iter().find(|g| g.selected).cloned();

    let mut selected_user_groups = rows
        .iter()
        .filter(|r| Some(r.user_id) == selected_user_id)
        .enumerate()
        .map(|(idx, r)| UserAssignedGroupRow {
            ordinal: idx + 1,
            id: r.group_id,
            name: r.group_name.clone(),
            description: r.group_description.clone(),
            is_virtual: r.group_is_virtual,
        })
        .collect::<Vec<_>>();

    selected_user_groups.sort_by_key(|g| g.name.to_lowercase());
    for (idx, g) in selected_user_groups.iter_mut().enumerate() {
        g.ordinal = idx + 1;
    }

    let selected_user_patterns = if let Some(user_id) = selected_user_id {
        sqlx::query_as::<_, UserGroupPatternRow>(
            r#"
            SELECT id, pattern, is_include, priority
            FROM user_group_patterns
            WHERE tenant_id = $1
              AND user_id = $2
              AND deleted_at IS NULL
            ORDER BY priority ASC, pattern ASC
            "#,
        )
        .bind(default_tenant_id())
        .bind(user_id)
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut selected_group_users = rows
        .iter()
        .filter(|r| Some(r.group_id) == selected_group_id)
        .enumerate()
        .map(|(idx, r)| GroupAssignedUserRow {
            ordinal: idx + 1,
            id: r.user_id,
            username: r.username.clone(),
            email: r.email.clone(),
            first_name: r.first_name.clone(),
            last_name: r.last_name.clone(),
            auth_mode: r.auth_mode.clone(),
            is_active: r.is_active,
        })
        .collect::<Vec<_>>();

    selected_group_users.sort_by_key(|u| u.username.to_lowercase());
    for (idx, u) in selected_group_users.iter_mut().enumerate() {
        u.ordinal = idx + 1;
    }

    let available_groups = groups
        .iter()
        .filter(|g| {
            selected_user_id.is_some()
                && !selected_user_groups
                    .iter()
                    .any(|assigned| assigned.id == g.id)
        })
        .cloned()
        .collect::<Vec<_>>();

    let available_users = users
        .iter()
        .filter(|u| {
            selected_group_id.is_some()
                && !selected_group_users
                    .iter()
                    .any(|assigned| assigned.id == u.id)
        })
        .cloned()
        .collect::<Vec<_>>();

    render_template(MembershipsTemplate {
        sections: nav_items(AdminSection::Memberships),
        message: query.message,
        error: query.error,
        users,
        groups,
        selected_user,
        selected_group,
        selected_user_groups,
        selected_user_patterns,
        selected_group_users,
        available_groups,
        available_users,
        user_filter: query.user_filter.unwrap_or_default(),
        group_filter: query.group_filter.unwrap_or_default(),
    })
}

async fn memberships_add_groups_to_user(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    Form(form): Form<MembershipAddGroupsForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let fallback = format!("/admin/ui/memberships?user_id={user_id}#by-user");
    let return_path = memberships_return_path_from_referer(&headers, &fallback);

    let group_ids = parse_uuid_csv(form.group_ids_csv.as_deref());
    if group_ids.is_empty() {
        return redirect_with(&return_path, "error", "No group selected").into_response();
    }

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };

    for group_id in group_ids {
        if let Err(e) = sqlx::query(
            r#"INSERT INTO user_groups (tenant_id, user_id, group_id)
               VALUES ($1, $2, $3)
               ON CONFLICT (user_id, group_id) DO NOTHING"#,
        )
        .bind(default_tenant_id())
        .bind(user_id)
        .bind(group_id)
        .execute(&mut *tx)
        .await
        {
            return redirect_with(&return_path, "error", &format!("Add failed: {e}"))
                .into_response();
        }
    }

    match tx.commit().await {
        Ok(_) => redirect_with(&return_path, "message", "Groups assigned").into_response(),
        Err(e) => redirect_with(&return_path, "error", &format!("Add failed: {e}")).into_response(),
    }
}

async fn memberships_remove_group_from_user(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path((user_id, group_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let fallback = format!("/admin/ui/memberships?user_id={user_id}#by-user");
    let return_path = memberships_return_path_from_referer(&headers, &fallback);

    match sqlx::query(
        r#"DELETE FROM user_groups
           WHERE tenant_id = $1 AND user_id = $2 AND group_id = $3"#,
    )
    .bind(default_tenant_id())
    .bind(user_id)
    .bind(group_id)
    .execute(&state.db_pool)
    .await
    {
        Ok(_) => redirect_with(&return_path, "message", "Group removed from user").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Remove failed: {e}")).into_response()
        }
    }
}

async fn memberships_remove_groups_from_user(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    Form(form): Form<MembershipRemoveGroupsForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let fallback = format!("/admin/ui/memberships?user_id={user_id}#by-user");
    let return_path = memberships_return_path_from_referer(&headers, &fallback);
    let group_ids = parse_uuid_csv(form.group_ids_csv.as_deref());
    if group_ids.is_empty() {
        return redirect_with(&return_path, "error", "No group selected").into_response();
    }

    match sqlx::query(
        r#"DELETE FROM user_groups
           WHERE tenant_id = $1 AND user_id = $2 AND group_id = ANY($3::uuid[])"#,
    )
    .bind(default_tenant_id())
    .bind(user_id)
    .bind(&group_ids)
    .execute(&state.db_pool)
    .await
    {
        Ok(result) => redirect_with(
            &return_path,
            "message",
            &format!("Removed {} group assignments", result.rows_affected()),
        )
        .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Remove failed: {e}")).into_response()
        }
    }
}

async fn memberships_add_users_to_group(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Form(form): Form<MembershipAddUsersForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let fallback = format!("/admin/ui/memberships?group_id={group_id}#by-group");
    let return_path = memberships_return_path_from_referer(&headers, &fallback);

    let user_ids = parse_uuid_csv(form.user_ids_csv.as_deref());
    if user_ids.is_empty() {
        return redirect_with(&return_path, "error", "No user selected").into_response();
    }

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };

    for user_id in user_ids {
        if let Err(e) = sqlx::query(
            r#"INSERT INTO user_groups (tenant_id, user_id, group_id)
               VALUES ($1, $2, $3)
               ON CONFLICT (user_id, group_id) DO NOTHING"#,
        )
        .bind(default_tenant_id())
        .bind(user_id)
        .bind(group_id)
        .execute(&mut *tx)
        .await
        {
            return redirect_with(&return_path, "error", &format!("Add failed: {e}"))
                .into_response();
        }
    }

    match tx.commit().await {
        Ok(_) => redirect_with(&return_path, "message", "Users assigned").into_response(),
        Err(e) => redirect_with(&return_path, "error", &format!("Add failed: {e}")).into_response(),
    }
}

async fn memberships_remove_user_from_group(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let fallback = format!("/admin/ui/memberships?group_id={group_id}#by-group");
    let return_path = memberships_return_path_from_referer(&headers, &fallback);

    match sqlx::query(
        r#"DELETE FROM user_groups
           WHERE tenant_id = $1 AND user_id = $2 AND group_id = $3"#,
    )
    .bind(default_tenant_id())
    .bind(user_id)
    .bind(group_id)
    .execute(&state.db_pool)
    .await
    {
        Ok(_) => redirect_with(&return_path, "message", "User removed from group").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Remove failed: {e}")).into_response()
        }
    }
}

async fn memberships_remove_users_from_group(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Form(form): Form<MembershipRemoveUsersForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let fallback = format!("/admin/ui/memberships?group_id={group_id}#by-group");
    let return_path = memberships_return_path_from_referer(&headers, &fallback);
    let user_ids = parse_uuid_csv(form.user_ids_csv.as_deref());
    if user_ids.is_empty() {
        return redirect_with(&return_path, "error", "No user selected").into_response();
    }

    match sqlx::query(
        r#"DELETE FROM user_groups
           WHERE tenant_id = $1 AND group_id = $2 AND user_id = ANY($3::uuid[])"#,
    )
    .bind(default_tenant_id())
    .bind(group_id)
    .bind(&user_ids)
    .execute(&state.db_pool)
    .await
    {
        Ok(result) => redirect_with(
            &return_path,
            "message",
            &format!("Removed {} user assignments", result.rows_affected()),
        )
        .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Remove failed: {e}")).into_response()
        }
    }
}

async fn user_groups_redirect() -> impl IntoResponse {
    Redirect::to("/admin/ui/memberships#by-user")
}

async fn group_users_redirect() -> impl IntoResponse {
    Redirect::to("/admin/ui/memberships#by-group")
}

async fn clients_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let filter_q = query.q.unwrap_or_default();
    let search_patterns = filter_q
        .split_whitespace()
        .map(|term| format!("%{}%", term.to_lowercase()))
        .collect::<Vec<_>>();

    let rows = match sqlx::query_as::<_, ClientRow>(
        r#"SELECT id, client_id, name, redirect_uris, grant_types, scope, is_active, is_public,
                  groups_claim_mode, include_claim_maps, ignore_virtual_groups
           FROM oauth_clients
           WHERE deleted_at IS NULL
             AND (
               cardinality($1::text[]) = 0 OR
               lower(concat_ws(' ', client_id, name, scope, array_to_string(redirect_uris, ' '), array_to_string(grant_types, ' '), groups_claim_mode)) LIKE ALL($1::text[])
             )
           ORDER BY name ASC"#,
    )
    .bind(&search_patterns)
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/clients", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let deleted_rows = sqlx::query_as::<_, ClientRow>(
        r#"SELECT id, client_id, name, redirect_uris, grant_types, scope, is_active, is_public,
                  groups_claim_mode, include_claim_maps, ignore_virtual_groups
           FROM oauth_clients
           WHERE deleted_at IS NOT NULL
           ORDER BY deleted_at DESC
           LIMIT 50"#,
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let client_ids = rows.iter().map(|r| r.id).collect::<Vec<_>>();
    let client_patterns = if client_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, ClientGroupPatternRow>(
            r#"
            SELECT id, client_id, pattern, is_include, priority
            FROM oauth_client_group_patterns
            WHERE client_id = ANY($1::uuid[])
              AND deleted_at IS NULL
            ORDER BY priority ASC, pattern ASC
            "#,
        )
        .bind(&client_ids)
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default()
    };

    render_template(ClientsTemplate {
        sections: nav_items(AdminSection::Clients),
        message: query.message,
        error: query.error,
        rows,
        deleted_rows,
        client_patterns,
        filter_q,
    })
}

async fn clients_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<ClientCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path =
        q_return_path_from_referer(&headers, "/admin/ui/clients", "/admin/ui/clients");

    let is_public = parse_checkbox(&form.is_public);
    let is_active = parse_checkbox(&form.is_active);
    let groups_claim_mode = normalize_groups_claim_mode(form.groups_claim_mode.as_deref());
    let include_claim_maps = parse_checkbox(&form.include_claim_maps);
    let ignore_virtual_groups = parse_checkbox(&form.ignore_virtual_groups);
    let client_secret_hash = if is_public {
        None
    } else {
        let Some(secret) = form
            .client_secret
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            return redirect_with(
                &return_path,
                "error",
                "Confidential clients require client secret",
            )
            .into_response();
        };
        match simple_idm_core::auth::password::hash_password(secret) {
            Ok(v) => Some(v),
            Err(e) => {
                return redirect_with(&return_path, "error", &format!("Hash failed: {e}"))
                    .into_response();
            }
        }
    };

    let grants = {
        let from_flags = selected_grant_types_from_flags(
            &form.grant_authorization_code,
            &form.grant_refresh_token,
            &form.grant_client_credentials,
            &form.grant_device_code,
        );
        if from_flags.is_empty() {
            selected_grant_types(&form.grant_types, form.grant_types_csv.as_deref())
        } else {
            from_flags
        }
    };
    let scopes = {
        let from_flags = selected_scopes_from_flags(
            &form.scope_openid,
            &form.scope_profile,
            &form.scope_email,
            &form.scope_groups,
            &form.scope_offline_access,
        );
        if from_flags.is_empty() {
            selected_scope_string(&form.scopes, form.scope.as_deref())
        } else {
            from_flags.join(" ")
        }
    };

    let result = sqlx::query(
        r#"INSERT INTO oauth_clients
           (tenant_id, client_id, client_secret_hash, name, redirect_uris, grant_types, scope, is_active, is_public,
            groups_claim_mode, include_claim_maps, ignore_virtual_groups)
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(form.client_id.trim())
    .bind(client_secret_hash)
    .bind(form.name.trim())
    .bind(split_csv(&form.redirect_uris))
    .bind(grants)
    .bind(scopes)
    .bind(is_active)
    .bind(is_public)
    .bind(groups_claim_mode)
    .bind(include_claim_maps)
    .bind(ignore_virtual_groups)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(&return_path, "message", "Client created").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Create failed: {e}")).into_response()
        }
    }
}

async fn clients_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<ClientUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path =
        q_return_path_from_referer(&headers, "/admin/ui/clients", "/admin/ui/clients");

    let is_active = parse_checkbox(&form.is_active);
    let is_public = parse_checkbox(&form.is_public);
    let groups_claim_mode = normalize_groups_claim_mode(form.groups_claim_mode.as_deref());
    let include_claim_maps = parse_checkbox(&form.include_claim_maps);
    let ignore_virtual_groups = parse_checkbox(&form.ignore_virtual_groups);

    let grants = {
        let from_flags = selected_grant_types_from_flags(
            &form.grant_authorization_code,
            &form.grant_refresh_token,
            &form.grant_client_credentials,
            &form.grant_device_code,
        );
        if from_flags.is_empty() {
            selected_grant_types(&form.grant_types, form.grant_types_csv.as_deref())
        } else {
            from_flags
        }
    };
    let scopes = {
        let from_flags = selected_scopes_from_flags(
            &form.scope_openid,
            &form.scope_profile,
            &form.scope_email,
            &form.scope_groups,
            &form.scope_offline_access,
        );
        if from_flags.is_empty() {
            selected_scope_string(&form.scopes, form.scope.as_deref())
        } else {
            from_flags.join(" ")
        }
    };
    let existing_secret_hash = match sqlx::query_scalar::<_, Option<String>>(
        "SELECT client_secret_hash FROM oauth_clients WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return redirect_with(&return_path, "error", "Client not found").into_response();
        }
        Err(e) => {
            return redirect_with(&return_path, "error", &format!("DB error: {e}")).into_response();
        }
    };
    let client_secret_hash_update = match form
        .client_secret
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(secret) => match simple_idm_core::auth::password::hash_password(secret) {
            Ok(v) => Some(v),
            Err(e) => {
                return redirect_with(&return_path, "error", &format!("Hash failed: {e}"))
                    .into_response();
            }
        },
        None => None,
    };
    if !is_public && client_secret_hash_update.is_none() && existing_secret_hash.is_none() {
        return redirect_with(
            &return_path,
            "error",
            "Confidential clients require client secret",
        )
        .into_response();
    }

    let result = sqlx::query(
        r#"UPDATE oauth_clients
           SET client_id=$2,
               name=$3,
               redirect_uris=$4,
               grant_types=$5,
               scope=$6,
               is_active=$7,
               is_public=$8,
               client_secret_hash = CASE
                 WHEN $8 THEN NULL
                 WHEN $9::text IS NOT NULL THEN $9
                 ELSE client_secret_hash
               END,
               groups_claim_mode=$10,
               include_claim_maps=$11,
               ignore_virtual_groups=$12,
               updated_at=NOW()
           WHERE id=$1"#,
    )
    .bind(id)
    .bind(form.client_id.trim())
    .bind(form.name.trim())
    .bind(split_csv(&form.redirect_uris))
    .bind(grants)
    .bind(scopes)
    .bind(is_active)
    .bind(is_public)
    .bind(client_secret_hash_update)
    .bind(groups_claim_mode)
    .bind(include_claim_maps)
    .bind(ignore_virtual_groups)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(&return_path, "message", "Client updated").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Update failed: {e}")).into_response()
        }
    }
}

async fn client_patterns_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
    Form(form): Form<PatternCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path =
        q_return_path_from_referer(&headers, "/admin/ui/clients", "/admin/ui/clients");
    if form.pattern.trim().is_empty() {
        return redirect_with(&return_path, "error", "Pattern is required").into_response();
    }

    match sqlx::query(
        r#"
        INSERT INTO oauth_client_group_patterns (tenant_id, client_id, pattern, is_include, priority)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(default_tenant_id())
    .bind(client_id)
    .bind(form.pattern.trim())
    .bind(pattern_mode_to_bool(&form.mode))
    .bind(pattern_priority(form.priority))
    .execute(&state.db_pool)
    .await
    {
        Ok(_) => redirect_with(&return_path, "message", "Client pattern created").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Pattern create failed: {e}"))
                .into_response()
        }
    }
}

async fn client_patterns_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path((client_id, pattern_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<PatternUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path =
        q_return_path_from_referer(&headers, "/admin/ui/clients", "/admin/ui/clients");
    if form.pattern.trim().is_empty() {
        return redirect_with(&return_path, "error", "Pattern is required").into_response();
    }

    match sqlx::query(
        r#"
        UPDATE oauth_client_group_patterns
        SET pattern = $3, is_include = $4, priority = $5
        WHERE id = $1 AND client_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(pattern_id)
    .bind(client_id)
    .bind(form.pattern.trim())
    .bind(pattern_mode_to_bool(&form.mode))
    .bind(pattern_priority(form.priority))
    .execute(&state.db_pool)
    .await
    {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "Client pattern updated").into_response()
        }
        Ok(_) => redirect_with(&return_path, "error", "Client pattern not found").into_response(),
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Pattern update failed: {e}"),
        )
        .into_response(),
    }
}

async fn client_patterns_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path((client_id, pattern_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path =
        q_return_path_from_referer(&headers, "/admin/ui/clients", "/admin/ui/clients");

    match sqlx::query(
        r#"
        UPDATE oauth_client_group_patterns
        SET deleted_at = NOW()
        WHERE id = $1 AND client_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(pattern_id)
    .bind(client_id)
    .execute(&state.db_pool)
    .await
    {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "Client pattern deleted").into_response()
        }
        Ok(_) => redirect_with(&return_path, "error", "Client pattern not found").into_response(),
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Pattern delete failed: {e}"),
        )
        .into_response(),
    }
}

async fn clients_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path =
        q_return_path_from_referer(&headers, "/admin/ui/clients", "/admin/ui/clients");

    let result = sqlx::query(
        r#"UPDATE oauth_clients
           SET is_active=false, deleted_at=NOW(), updated_at=NOW()
           WHERE id=$1 AND deleted_at IS NULL"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(&return_path, "message", "Client deactivated (safe delete)")
            .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Deactivate failed: {e}")).into_response()
        }
    }
}

async fn clients_restore(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path =
        q_return_path_from_referer(&headers, "/admin/ui/clients", "/admin/ui/clients");

    let result = sqlx::query(
        r#"UPDATE oauth_clients
           SET deleted_at = NULL, updated_at = NOW()
           WHERE id = $1 AND deleted_at IS NOT NULL"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "Client restored").into_response()
        }
        Ok(_) => redirect_with(&return_path, "error", "Client not found in deleted clients")
            .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Restore failed: {e}")).into_response()
        }
    }
}

async fn claims_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let mut page_error = query.error.clone();
    let claim_maps = match sqlx::query_as::<_, ClaimMapRow>(
        r#"SELECT cm.id,
                  cm.client_id,
                  cm.group_id,
                  oc.name AS client_name,
                  g.name AS group_name,
                  cm.claim_name,
                  cm.claim_value,
                  cm.claim_value_json,
                  cm.claim_value_kind
           FROM claim_maps cm
           JOIN oauth_clients oc ON oc.id = cm.client_id
           LEFT JOIN groups g ON g.id = cm.group_id
           WHERE cm.deleted_at IS NULL
             AND oc.deleted_at IS NULL
             AND (g.id IS NULL OR g.deleted_at IS NULL)
           ORDER BY oc.name, g.name NULLS LAST, cm.claim_name"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            page_error = Some(format!("DB error: {e}"));
            Vec::new()
        }
    };

    let clients = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, name FROM oauth_clients WHERE deleted_at IS NULL ORDER BY name",
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();
    let groups = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, name FROM groups WHERE deleted_at IS NULL ORDER BY name",
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let selected_client_id = query.client_id.or_else(|| clients.first().map(|c| c.0));
    let client_rows = clients
        .iter()
        .map(|(id, name)| ClientClaimsRow {
            id: *id,
            name: name.clone(),
            selected: Some(*id) == selected_client_id,
            claims_count: claim_maps.iter().filter(|m| m.client_id == *id).count(),
        })
        .collect::<Vec<_>>();
    let selected_client = client_rows.iter().find(|r| r.selected).cloned();
    let selected_client_claim_maps = claim_maps
        .iter()
        .filter(|m| Some(m.client_id) == selected_client_id)
        .cloned()
        .enumerate()
        .map(|(idx, row)| ClientClaimMapView {
            ordinal: idx + 1,
            row,
        })
        .collect::<Vec<_>>();

    let selected_group_id = query.group_id.or_else(|| groups.first().map(|g| g.0));
    let group_rows = groups
        .iter()
        .map(|(id, name)| GroupClaimsRow {
            id: Some(*id),
            name: name.clone(),
            selected: Some(*id) == selected_group_id,
            claims_count: claim_maps
                .iter()
                .filter(|m| m.group_id == Some(*id))
                .count(),
        })
        .collect::<Vec<_>>();
    let selected_group = group_rows.iter().find(|r| r.selected).cloned();
    let selected_group_claim_maps = claim_maps
        .into_iter()
        .filter(|m| m.group_id == selected_group_id)
        .enumerate()
        .map(|(idx, row)| GroupClaimMapView {
            ordinal: idx + 1,
            row,
        })
        .collect::<Vec<_>>();

    let deleted_claim_maps = sqlx::query_as::<_, ClaimMapRow>(
        r#"
        SELECT cm.id,
               cm.client_id,
               cm.group_id,
               oc.name AS client_name,
               g.name AS group_name,
               cm.claim_name,
               cm.claim_value,
               cm.claim_value_json,
               cm.claim_value_kind
        FROM claim_maps cm
        JOIN oauth_clients oc ON oc.id = cm.client_id
        LEFT JOIN groups g ON g.id = cm.group_id
        WHERE cm.deleted_at IS NOT NULL
          AND oc.deleted_at IS NULL
          AND (g.id IS NULL OR g.deleted_at IS NULL)
        ORDER BY cm.deleted_at DESC
        LIMIT 50
        "#,
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let claim_map_ids = selected_client_claim_maps
        .iter()
        .map(|m| m.row.id)
        .chain(selected_group_claim_maps.iter().map(|m| m.row.id))
        .collect::<Vec<_>>();
    let claim_patterns = if claim_map_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, ClaimMapPatternRow>(
            r#"
            SELECT id, claim_map_id, pattern, is_include, priority
            FROM claim_map_patterns
            WHERE claim_map_id = ANY($1::uuid[])
              AND deleted_at IS NULL
            ORDER BY priority ASC, pattern ASC
            "#,
        )
        .bind(&claim_map_ids)
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default()
    };

    render_template(ClaimsTemplate {
        sections: nav_items(AdminSection::Claims),
        message: query.message,
        error: page_error,
        client_rows,
        groups,
        selected_client,
        selected_client_claim_maps,
        group_rows,
        clients,
        selected_group,
        selected_group_claim_maps,
        deleted_claim_maps,
        claim_patterns,
    })
}

async fn client_claims_redirect() -> impl IntoResponse {
    Redirect::to("/admin/ui/claims#by-client")
}

async fn group_claims_redirect() -> impl IntoResponse {
    Redirect::to("/admin/ui/claims#by-group")
}

async fn client_claims_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Form(form): Form<ClaimMapCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let client_id = match Uuid::parse_str(form.client_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            let return_path = scoped_return_path_from_referer(
                &headers,
                "/admin/ui/claims",
                "/admin/ui/claims",
                &["client_id", "group_id"],
            );
            return redirect_with(&return_path, "error", "Invalid client_id").into_response();
        }
    };

    let group_id = form
        .group_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| Uuid::parse_str(v).ok());

    let (claim_value_kind, claim_value, claim_value_json) =
        claim_value_columns(form.claim_value_kind.trim(), &form.claim_value);

    let return_path = if headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("/admin/ui/claims"))
    {
        scoped_return_path_from_referer(
            &headers,
            "/admin/ui/claims",
            "/admin/ui/claims",
            &["client_id", "group_id"],
        )
    } else {
        scoped_return_path_from_referer(
            &headers,
            "/admin/ui/client-claims",
            "/admin/ui/client-claims",
            &["client_id"],
        )
    };
    let result = sqlx::query(
        r#"INSERT INTO claim_maps (tenant_id, client_id, group_id, claim_name, claim_value, claim_value_kind, claim_value_json)
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5, $6)"#,
    )
    .bind(client_id)
    .bind(group_id)
    .bind(form.claim_name.trim())
    .bind(claim_value)
    .bind(claim_value_kind)
    .bind(claim_value_json)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(&return_path, "message", "Claim rule created").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Create failed: {e}")).into_response()
        }
    }
}

async fn claim_maps_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<ClaimMapUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (prefix, fallback, keys): (&str, &str, &[&str]) = if referer.contains("/admin/ui/claims") {
        (
            "/admin/ui/claims",
            "/admin/ui/claims",
            &["client_id", "group_id"],
        )
    } else if referer.contains("/admin/ui/group-claims") {
        (
            "/admin/ui/group-claims",
            "/admin/ui/group-claims",
            &["group_id"],
        )
    } else {
        (
            "/admin/ui/client-claims",
            "/admin/ui/client-claims",
            &["client_id"],
        )
    };
    let return_path = scoped_return_path_from_referer(&headers, prefix, fallback, keys);
    let (claim_value_kind, claim_value, claim_value_json) =
        claim_value_columns(form.claim_value_kind.trim(), &form.claim_value);

    let result = sqlx::query(
        r#"
        UPDATE claim_maps
        SET claim_name = $2,
            claim_value = $3,
            claim_value_kind = $4,
            claim_value_json = $5,
            updated_at = NOW()
        WHERE id = $1
          AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .bind(form.claim_name.trim())
    .bind(claim_value)
    .bind(claim_value_kind)
    .bind(claim_value_json)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(&return_path, "message", "Claim rule updated").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Update failed: {e}")).into_response()
        }
    }
}

async fn claim_maps_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (prefix, fallback, keys): (&str, &str, &[&str]) = if referer.contains("/admin/ui/claims") {
        (
            "/admin/ui/claims",
            "/admin/ui/claims",
            &["client_id", "group_id"],
        )
    } else if referer.contains("/admin/ui/group-claims") {
        (
            "/admin/ui/group-claims",
            "/admin/ui/group-claims",
            &["group_id"],
        )
    } else {
        (
            "/admin/ui/client-claims",
            "/admin/ui/client-claims",
            &["client_id"],
        )
    };
    let return_path = scoped_return_path_from_referer(&headers, prefix, fallback, keys);
    let result = sqlx::query(
        r#"UPDATE claim_maps SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with(&return_path, "message", "Claim rule deactivated").into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Deactivate failed: {e}")).into_response()
        }
    }
}

async fn claim_maps_restore(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let return_path = scoped_return_path_from_referer(
        &headers,
        "/admin/ui/claims",
        "/admin/ui/claims",
        &["client_id", "group_id"],
    );
    let result = sqlx::query(
        r#"
        UPDATE claim_maps
        SET deleted_at = NULL, updated_at = NOW()
        WHERE id = $1 AND deleted_at IS NOT NULL
        "#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "Claim rule restored").into_response()
        }
        Ok(_) => redirect_with(
            &return_path,
            "error",
            "Claim rule not found in deleted rules",
        )
        .into_response(),
        Err(e) => {
            redirect_with(&return_path, "error", &format!("Restore failed: {e}")).into_response()
        }
    }
}

async fn claim_patterns_create(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(claim_map_id): Path<Uuid>,
    Form(form): Form<PatternCreateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = scoped_return_path_from_referer(
        &headers,
        "/admin/ui/claims",
        "/admin/ui/claims",
        &["client_id", "group_id"],
    );
    if form.pattern.trim().is_empty() {
        return redirect_with(&return_path, "error", "Pattern is required").into_response();
    }

    match sqlx::query(
        r#"
        INSERT INTO claim_map_patterns (tenant_id, claim_map_id, pattern, is_include, priority)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(default_tenant_id())
    .bind(claim_map_id)
    .bind(form.pattern.trim())
    .bind(pattern_mode_to_bool(&form.mode))
    .bind(pattern_priority(form.priority))
    .execute(&state.db_pool)
    .await
    {
        Ok(_) => redirect_with(&return_path, "message", "Claim pattern created").into_response(),
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Pattern create failed: {e}"),
        )
        .into_response(),
    }
}

async fn claim_patterns_update(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path((claim_map_id, pattern_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<PatternUpdateForm>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = scoped_return_path_from_referer(
        &headers,
        "/admin/ui/claims",
        "/admin/ui/claims",
        &["client_id", "group_id"],
    );
    if form.pattern.trim().is_empty() {
        return redirect_with(&return_path, "error", "Pattern is required").into_response();
    }

    match sqlx::query(
        r#"
        UPDATE claim_map_patterns
        SET pattern = $3, is_include = $4, priority = $5
        WHERE id = $1 AND claim_map_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(pattern_id)
    .bind(claim_map_id)
    .bind(form.pattern.trim())
    .bind(pattern_mode_to_bool(&form.mode))
    .bind(pattern_priority(form.priority))
    .execute(&state.db_pool)
    .await
    {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "Claim pattern updated").into_response()
        }
        Ok(_) => redirect_with(&return_path, "error", "Claim pattern not found").into_response(),
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Pattern update failed: {e}"),
        )
        .into_response(),
    }
}

async fn claim_patterns_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path((claim_map_id, pattern_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }
    let return_path = scoped_return_path_from_referer(
        &headers,
        "/admin/ui/claims",
        "/admin/ui/claims",
        &["client_id", "group_id"],
    );

    match sqlx::query(
        r#"
        UPDATE claim_map_patterns
        SET deleted_at = NOW()
        WHERE id = $1 AND claim_map_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(pattern_id)
    .bind(claim_map_id)
    .execute(&state.db_pool)
    .await
    {
        Ok(done) if done.rows_affected() > 0 => {
            redirect_with(&return_path, "message", "Claim pattern deleted").into_response()
        }
        Ok(_) => redirect_with(&return_path, "error", "Claim pattern not found").into_response(),
        Err(e) => redirect_with(
            &return_path,
            "error",
            &format!("Pattern delete failed: {e}"),
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_update_form_accepts_empty_auth_provider_id() {
        let form: UserUpdateForm = serde_urlencoded::from_str(
            "email=user%40example.com&password=&auth_mode=local&auth_provider_id=&first_name=John&last_name=Doe",
        )
        .unwrap();

        assert_eq!(form.auth_provider_id, None);
        assert_eq!(form.first_name.as_deref(), Some("John"));
        assert_eq!(form.last_name.as_deref(), Some("Doe"));
    }

    #[test]
    fn user_create_form_accepts_empty_auth_provider_id() {
        let form: UserCreateForm = serde_urlencoded::from_str(
            "username=user&email=user%40example.com&password=secret&auth_mode=local&auth_provider_id=",
        )
        .unwrap();

        assert_eq!(form.auth_provider_id, None);
    }
}
