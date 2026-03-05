use askama::Template;
use axum::{
    extract::{Form, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use rand::RngExt;
use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde_json::json;
use simple_idm_core::{
    admin::middleware::AdminAuth,
    db::{DbPool, models::User},
    oauth2::{self, OAuth2State},
};
use sha2::Digest;
use sqlx::{FromRow, Row};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

const ADMIN_SESSION_COOKIE: &str = "sidm_admin_session";
const ADMIN_SESSION_TTL_SECONDS: i64 = 8 * 60 * 60;

#[derive(Clone)]
pub struct WebAdminState {
    pub db_pool: DbPool,
    pub oauth_state: Arc<OAuth2State>,
    pub admin_auth: AdminAuth,
    pub secure_cookies: bool,
    pub ad_onboarding_token_ttl_seconds: i64,
    pub admin_sessions: Arc<RwLock<HashMap<String, (String, DateTime<Utc>)>>>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    token: String,
}

#[derive(Debug, Deserialize)]
pub struct UserCreateForm {
    username: String,
    email: String,
    password: Option<String>,
    auth_mode: Option<String>,
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
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserAdMappingsApplyForm {
    mappings_json: String,
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
pub struct ClientCreateForm {
    client_id: String,
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
    is_public: Option<String>,
    is_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientUpdateForm {
    client_id: String,
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
pub struct AdOnboardingForm {
    token: String,
    login: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    message: Option<String>,
    error: Option<String>,
    ad_link: Option<String>,
    q: Option<String>,
    status: Option<String>,
    note: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_string_or_seq")]
    letters: Option<Vec<String>>,
    page: Option<u32>,
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
    is_active: bool,
}

#[derive(Debug, Clone, FromRow)]
struct GroupRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    is_virtual: bool,
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
struct ClaimMapRow {
    client_name: String,
    group_name: Option<String>,
    claim_name: String,
    claim_value: Option<serde_json::Value>,
    claim_value_kind: String,
}

#[derive(Debug, Clone, FromRow)]
struct UserGroupRow {
    username: String,
    email: String,
    group_name: String,
}

#[derive(Debug, Clone)]
struct GroupUsersRow {
    group_name: String,
    users: String,
}

#[derive(Debug, Clone)]
struct ClientClaimsRow {
    client_name: String,
    claims: String,
}

#[derive(Debug, Clone)]
struct GroupClaimsRow {
    group_name: String,
    claims: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminSection {
    Dashboard,
    Users,
    Groups,
    UserGroups,
    GroupUsers,
    Clients,
    ClientClaims,
    GroupClaims,
}

impl AdminSection {
    fn all() -> [Self; 8] {
        [
            Self::Dashboard,
            Self::Users,
            Self::Groups,
            Self::UserGroups,
            Self::GroupUsers,
            Self::Clients,
            Self::ClientClaims,
            Self::GroupClaims,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Users => "Users",
            Self::Groups => "Groups",
            Self::UserGroups => "User groups",
            Self::GroupUsers => "Group users",
            Self::Clients => "Clients",
            Self::ClientClaims => "Client claims",
            Self::GroupClaims => "Group claims",
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Dashboard => "/admin/ui/",
            Self::Users => "/admin/ui/users",
            Self::Groups => "/admin/ui/groups",
            Self::UserGroups => "/admin/ui/user-groups",
            Self::GroupUsers => "/admin/ui/group-users",
            Self::Clients => "/admin/ui/clients",
            Self::ClientClaims => "/admin/ui/client-claims",
            Self::GroupClaims => "/admin/ui/group-claims",
        }
    }
}

#[derive(Template)]
#[template(path = "admin/login.html")]
struct LoginTemplate<'a> {
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "admin/users.html")]
struct UsersTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    ad_link: Option<String>,
    rows: Vec<UserRow>,
    ad_modal_data: Vec<UserAdMappingModalData>,
    ad_onboarding_tokens: Vec<AdOnboardingTokenView>,
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
    rows: Vec<GroupRow>,
}

#[derive(Template)]
#[template(path = "admin/user_groups.html")]
struct UserGroupsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<UserGroupRow>,
}

#[derive(Template)]
#[template(path = "admin/group_users.html")]
struct GroupUsersTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<GroupUsersRow>,
}

#[derive(Template)]
#[template(path = "admin/clients.html")]
struct ClientsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<ClientRow>,
}

#[derive(Template)]
#[template(path = "admin/client_claims.html")]
struct ClientClaimsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<ClientClaimsRow>,
    clients: Vec<(Uuid, String)>,
    groups: Vec<(Uuid, String)>,
}

#[derive(Template)]
#[template(path = "admin/group_claims.html")]
struct GroupClaimsTemplate {
    sections: Vec<NavItem>,
    message: Option<String>,
    error: Option<String>,
    rows: Vec<GroupClaimsRow>,
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
    claim_maps_total: i64,
    managed_domains: Vec<String>,
}

pub fn router(state: WebAdminState) -> Router {
    Router::new()
        .route("/ad/onboarding", get(ad_onboarding_page).post(ad_onboarding_submit))
        .route("/admin/ui/static/users.js", get(users_js))
        .route("/admin/ui", get(ui_dashboard))
        .route("/admin/ui/", get(ui_dashboard))
        .route("/admin/ui/login", get(login_page).post(login_submit))
        .route("/admin/ui/logout", post(logout_submit))
        .route("/admin/ui/users", get(users_page))
        .route("/admin/ui/ad-onboarding", get(ad_onboarding_tokens_page))
        .route("/admin/ui/ad-roles", get(ad_roles_page))
        .route("/admin/ui/ad-role-mappings", get(ad_role_mappings_page))
        .route("/admin/ui/ad-role-mappings/create", post(ad_role_mappings_create))
        .route(
            "/admin/ui/ad-role-mappings/{id}/deactivate",
            post(ad_role_mappings_deactivate),
        )
        .route("/admin/ui/users/create", post(users_create))
        .route("/admin/ui/users/import", get(users_import_page).post(users_import_submit))
        .route("/admin/ui/users/{id}/update", post(users_update))
        .route("/admin/ui/users/{id}/deactivate", post(users_deactivate))
        .route(
            "/admin/ui/ad-onboarding/delete",
            post(ad_onboarding_tokens_bulk_delete),
        )
        .route("/admin/ui/users/{id}/ad-mappings/apply", post(users_ad_mappings_apply))
        .route(
            "/admin/ui/users/{id}/ad-onboarding-link",
            post(users_ad_onboarding_link),
        )
        .route("/admin/ui/groups", get(groups_page))
        .route("/admin/ui/groups/create", post(groups_create))
        .route("/admin/ui/groups/{id}/update", post(groups_update))
        .route("/admin/ui/groups/{id}/deactivate", post(groups_deactivate))
        .route("/admin/ui/user-groups", get(user_groups_page))
        .route("/admin/ui/group-users", get(group_users_page))
        .route("/admin/ui/clients", get(clients_page))
        .route("/admin/ui/clients/create", post(clients_create))
        .route("/admin/ui/clients/{id}/update", post(clients_update))
        .route("/admin/ui/clients/{id}/deactivate", post(clients_deactivate))
        .route("/admin/ui/client-claims", get(client_claims_page))
        .route("/admin/ui/client-claims/create", post(client_claims_create))
        .route("/admin/ui/group-claims", get(group_claims_page))
        .with_state(state)
}

async fn users_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        USERS_PAGE_JS,
    )
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
        resultsRoot.replaceWith(nextResults);
        history.replaceState({}, '', url);
        initAdMapForms();
        applyFocusFromUrlParams(new URL(url, window.location.origin).searchParams);
      } catch (_) {
        window.location.assign(url);
      } finally {
        const newRoot = document.getElementById('users-results');
        if (newRoot) newRoot.style.opacity = '';
      }
    }

    let shouldAutoApplyPersisted = false;
    if (!hasQueryState) {
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
    if (!tbody || !jsonInput || !addBtn) return;

    function refreshDraftTable() {
      tbody.innerHTML = '';
      for (const [key, item] of draft.entries()) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code class="small">${item.external_role}</code></td>
          <td>${item.group_name}</td>
          <td><input type="number" class="form-control form-control-sm ad-priority" data-key="${key}" value="${item.priority}" style="max-width:100px;"></td>
          <td><button type="button" class="btn btn-sm btn-outline-danger ad-remove" data-key="${key}">Remove</button></td>
        `;
        tbody.appendChild(tr);
      }
      jsonInput.value = JSON.stringify(Array.from(draft.values()).map(v => ({
        external_role: v.external_role,
        group_id: v.group_id,
        priority: Number(v.priority) || 100,
        mode: 'add'
      })));
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
              external_role: r.value,
              group_id: g.value,
              group_name: groupLabel,
              priority: 100
            });
          }
        });
      });
      refreshDraftTable();
    });

    tbody.addEventListener('click', (e) => {
      const btn = e.target.closest('.ad-remove');
      if (!btn) return;
      draft.delete(btn.getAttribute('data-key'));
      refreshDraftTable();
    });

    tbody.addEventListener('input', (e) => {
      const inp = e.target.closest('.ad-priority');
      if (!inp) return;
      const key = inp.getAttribute('data-key');
      if (!draft.has(key)) return;
      const item = draft.get(key);
      item.priority = Number(inp.value) || 100;
      draft.set(key, item);
      jsonInput.value = JSON.stringify(Array.from(draft.values()).map(v => ({
        external_role: v.external_role,
        group_id: v.group_id,
        priority: Number(v.priority) || 100,
        mode: 'add'
      })));
    });

    form.addEventListener('submit', (e) => {
      if (draft.size === 0) {
        e.preventDefault();
        alert('No mappings selected.');
      }
    });
  });
  }
  initAdMapForms();

  const tokenStatusFilter = document.getElementById('ad-token-status-filter');
  const tokenRows = Array.from(document.querySelectorAll('.ad-token-row'));
  if (tokenStatusFilter) {
    tokenStatusFilter.addEventListener('change', () => {
      const status = tokenStatusFilter.value;
      tokenRows.forEach((row) => {
        const rowStatus = row.getAttribute('data-status') || 'all';
        row.style.display = status === 'all' || status === rowStatus ? '' : 'none';
      });
    });
  }

  const tokenSelectAll = document.getElementById('ad-token-select-all');
  const tokenDeleteForm = document.querySelector('form[action=\"/admin/ui/ad-onboarding/delete\"]');
  const tokenHashesCsv = document.getElementById('ad-token-hashes-csv');
  if (tokenSelectAll) {
    tokenSelectAll.addEventListener('change', () => {
      document.querySelectorAll('.ad-token-check').forEach((el) => {
        const row = el.closest('tr');
        if (!row || row.style.display === 'none') return;
        el.checked = tokenSelectAll.checked;
      });
    });
  }
  if (tokenDeleteForm && tokenHashesCsv) {
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
});
"#;

fn parse_checkbox(v: &Option<String>) -> bool {
    v.as_deref().is_some_and(|x| x == "on" || x == "true" || x == "1")
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
        "mixed" => "mixed".to_string(),
        "ad" => "mixed".to_string(),
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

async fn require_admin_token(state: &WebAdminState, headers: &HeaderMap) -> Result<String, Redirect> {
    let Some(session_id) = session_id_from_cookie(headers) else {
        return Err(Redirect::to("/admin/ui/login"));
    };

    let session = {
        let sessions = state.admin_sessions.read().await;
        sessions.get(&session_id).cloned()
    };
    let Some((token, expires_at)) = session else {
        return Err(Redirect::to("/admin/ui/login"));
    };
    if Utc::now() >= expires_at {
        let mut sessions = state.admin_sessions.write().await;
        sessions.remove(&session_id);
        return Err(Redirect::to("/admin/ui/login?error=Session%20expired"));
    }

    if validate_admin_token(state, &token).await {
        Ok(token)
    } else {
        let mut sessions = state.admin_sessions.write().await;
        sessions.remove(&session_id);
        Err(Redirect::to("/admin/ui/login?error=Invalid%20admin%20token"))
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

    let users_total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL",
    )
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
        "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND auth_mode = 'mixed'",
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
    let groups_total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM groups WHERE deleted_at IS NULL",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);
    let clients_total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM oauth_clients WHERE deleted_at IS NULL",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);
    let claim_maps_total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM claim_maps WHERE deleted_at IS NULL",
    )
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
        claim_maps_total,
        managed_domains,
    })
}

async fn login_page(Query(query): Query<PageQuery>) -> Response {
    render_template(LoginTemplate {
        error: query.error.as_deref(),
    })
}

async fn login_submit(
    State(state): State<WebAdminState>,
    Form(form): Form<LoginForm>,
) -> Response {
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

    (
        [(header::SET_COOKIE, cookie)],
        Redirect::to("/admin/ui/users"),
    )
        .into_response()
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
    ([(header::SET_COOKIE, cookie)], Redirect::to("/admin/ui/login")).into_response()
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
        return redirect_with("/ad/onboarding", "error", "Missing onboarding token").into_response();
    }
    if form.login.trim().is_empty() {
        return redirect_with(
            &format!("/ad/onboarding?token={}", urlencoding::encode(form.token.trim())),
            "error",
            "Missing AD login",
        )
        .into_response();
    }
    if form.password.is_empty() {
        return redirect_with(
            &format!("/ad/onboarding?token={}", urlencoding::encode(form.token.trim())),
            "error",
            "Missing AD password",
        )
        .into_response();
    }

    let token_hash = onboarding_token_hash(form.token.trim());
    let row = match sqlx::query(
        r#"
        SELECT t.user_id, u.id, u.username, u.tenant_id, t.expires_at, t.used_at
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
                .into_response()
        }
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response()
        }
    };

    let expires_at = match row.try_get::<DateTime<Utc>, _>("expires_at") {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response()
        }
    };
    let used_at = match row.try_get::<Option<DateTime<Utc>>, _>("used_at") {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response()
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
        return redirect_with("/ad/onboarding", "error", "Onboarding token was already used")
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
        return redirect_with("/ad/onboarding", "error", "Onboarding token expired").into_response();
    }

    let ldap_cfg = match &state.oauth_state.ldap_auth {
        Some(v) => v.clone(),
        None => {
            return redirect_with("/ad/onboarding", "error", "AD auth is not enabled")
                .into_response()
        }
    };

    if let Err(e) =
        simple_idm_ad_auth::verify_ldap_password(&ldap_cfg, form.login.trim(), &form.password).await
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
            &format!("/ad/onboarding?token={}", urlencoding::encode(form.token.trim())),
            "error",
            &format!("AD login failed: {e}"),
        )
        .into_response();
    }

    let user_id = match row.try_get::<Uuid, _>("user_id") {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/ad/onboarding", "error", &format!("DB error: {e}"))
                .into_response()
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
                .into_response()
        }
    };

    if let Err(e) = oauth2::sync_ldap_roles_force(state.oauth_state.as_ref(), &user, form.login.trim()).await
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
            &format!("/ad/onboarding?token={}", urlencoding::encode(form.token.trim())),
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
               LOWER(CONCAT_WS(' ', username, email, COALESCE(first_name, ''), COALESCE(last_name, '')))
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
            return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}")).into_response();
        }
    };

    let total_pages = ((total_items + per_page - 1) / per_page).max(1) as u32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * per_page;

    let rows = match sqlx::query_as::<_, UserRow>(
        r#"SELECT id, username, email, first_name, last_name, recovery_email, phone_e164, last_sign_in_at, note, auth_mode, is_active
           FROM users
           WHERE deleted_at IS NULL
             AND (
               cardinality($1::text[]) = 0 OR
               LOWER(CONCAT_WS(' ', username, email, COALESCE(first_name, ''), COALESCE(last_name, '')))
                 LIKE ALL($1::text[])
             )
             AND ($2::boolean IS NULL OR is_active = $2)
             AND ($3::text IS NULL OR $3 = '' OR COALESCE(note, '') ILIKE '%' || $3 || '%')
             AND (
               cardinality($4::text[]) = 0 OR
               UPPER(LEFT(COALESCE(last_name, ''), 1)) = ANY($4::text[])
             )
           ORDER BY username ASC
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

    let ad_user_ids = rows
        .iter()
        .filter(|u| u.auth_mode == "mixed")
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

        ad_user_ids
            .into_iter()
            .map(|user_id| UserAdMappingModalData {
                user_id,
                ad_roles: by_user.remove(&user_id).unwrap_or_default(),
                groups: groups.clone(),
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

    render_template(UsersTemplate {
        sections: nav_items(AdminSection::Users),
        message: query.message,
        error: query.error,
        ad_link: query.ad_link,
        rows,
        ad_modal_data,
        ad_onboarding_tokens,
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
                .into_response()
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
        Ok(_) => redirect_with("/admin/ui/ad-role-mappings", "message", "Role mapping created")
            .into_response(),
        Err(e) => {
            redirect_with(
                "/admin/ui/ad-role-mappings",
                "error",
                &format!("Create failed: {e}"),
            )
            .into_response()
        }
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

    let auth_mode = normalize_auth_mode(form.auth_mode.as_deref());
    let is_active = parse_checkbox(&form.is_active);
    let password = form.password.as_deref().map(str::trim).filter(|v| !v.is_empty());
    let password_hash: Option<String> = match (auth_mode.as_str(), password) {
        ("federated", _) => None,
        (_, Some(p)) => match simple_idm_core::auth::password::hash_password(p) {
            Ok(h) => Some(h),
            Err(e) => {
                return redirect_with(
                    "/admin/ui/users",
                    "error",
                    &format!("Password hash failed: {e}"),
                )
                .into_response();
            }
        },
        ("local", None) => {
            return redirect_with(
                "/admin/ui/users",
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
             tenant_id, username, email, password_hash, is_active, auth_mode, password_disabled,
             first_name, last_name, recovery_email, phone_e164, note
           )
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(form.username.trim())
    .bind(form.email.trim().to_lowercase())
    .bind(password_hash)
    .bind(is_active)
    .bind(auth_mode)
    .bind(password_disabled)
    .bind(normalize_opt_form(form.first_name))
    .bind(normalize_opt_form(form.last_name))
    .bind(normalize_opt_form(form.recovery_email).map(|v| v.to_lowercase()))
    .bind(normalize_opt_form(form.phone_e164))
    .bind(normalize_opt_form(form.note))
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/users", "message", "User created").into_response(),
        Err(e) => redirect_with("/admin/ui/users", "error", &format!("Create failed: {e}"))
            .into_response(),
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

    let auth_mode = normalize_auth_mode(form.auth_mode.as_deref());
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
               SET email = $2, password_hash = NULL, is_active = $3, auth_mode = $4, password_disabled = $5, updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(form.email.trim().to_lowercase())
        .bind(is_active)
        .bind(auth_mode)
        .bind(password_disabled)
        .execute(&state.db_pool)
        .await
    } else if let Some(password) = new_password {
        match simple_idm_core::auth::password::hash_password(password) {
            Ok(hash) => {
                sqlx::query(
                    r#"UPDATE users
                       SET email = $2, password_hash = $3, is_active = $4, auth_mode = $5, password_disabled = $6, updated_at = NOW()
                       WHERE id = $1"#,
                )
                .bind(id)
                .bind(form.email.trim().to_lowercase())
                .bind(hash)
                .bind(is_active)
                .bind(auth_mode)
                .bind(password_disabled)
                .execute(&state.db_pool)
                .await
            }
            Err(e) => {
                return redirect_with("/admin/ui/users", "error", &format!("Hash failed: {e}"))
                    .into_response();
            }
        }
    } else {
        sqlx::query(
            r#"UPDATE users
               SET email = $2, is_active = $3, auth_mode = $4, password_disabled = $5, updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(form.email.trim().to_lowercase())
        .bind(is_active)
        .bind(auth_mode)
        .bind(password_disabled)
        .execute(&state.db_pool)
        .await
    };

    match result {
        Ok(_) => redirect_with("/admin/ui/users", "message", "User updated").into_response(),
        Err(e) => redirect_with("/admin/ui/users", "error", &format!("Update failed: {e}"))
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
                .into_response()
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
            Ok(Some(user_id)) => {
                sqlx::query(
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
                })
            }
            Ok(None) => {
                let generated_password = random_import_password();
                let password_hash = match simple_idm_core::auth::password::hash_password(&generated_password) {
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

    let result = sqlx::query(
        r#"UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/users", "message", "User deactivated (safe delete)")
            .into_response(),
        Err(e) => redirect_with("/admin/ui/users", "error", &format!("Deactivate failed: {e}"))
            .into_response(),
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

    let token_hashes = form
        .token_hashes_csv
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    if token_hashes.is_empty() {
        return redirect_with("/admin/ui/users", "error", "No onboarding token selected")
            .into_response();
    }

    let result = sqlx::query("DELETE FROM ad_onboarding_tokens WHERE token_hash = ANY($1)")
        .bind(&token_hashes)
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(done) => redirect_with(
            "/admin/ui/users",
            "message",
            &format!("Deleted onboarding tokens: {}", done.rows_affected()),
        )
        .into_response(),
        Err(e) => redirect_with("/admin/ui/users", "error", &format!("Delete failed: {e}"))
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct MappingDraftItem {
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

    let user = match sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return redirect_with("/admin/ui/users", "error", "User not found").into_response(),
        Err(e) => {
            return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}")).into_response()
        }
    };

    if user.auth_mode != "mixed" {
        return redirect_with(
            "/admin/ui/users",
            "error",
            "AD role mapping is available only for auth type 'ad'",
        )
        .into_response();
    }

    let items: Vec<MappingDraftItem> = match serde_json::from_str(form.mappings_json.trim()) {
        Ok(v) => v,
        Err(e) => {
            return redirect_with(
                "/admin/ui/users",
                "error",
                &format!("Invalid mappings payload: {e}"),
            )
            .into_response();
        }
    };

    if items.is_empty() {
        return redirect_with("/admin/ui/users", "error", "No mappings selected").into_response();
    }

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}")).into_response(),
    };
    let mut created = 0usize;
    for item in &items {
        let Ok(group_id) = Uuid::parse_str(item.group_id.trim()) else {
            continue;
        };
        let mode = match item.mode.as_deref().unwrap_or("add") {
            "remove" => "remove",
            _ => "add",
        };
        let priority = item.priority.unwrap_or(100);
        if item.external_role.trim().is_empty() {
            continue;
        }
        let result = sqlx::query(
            r#"
            INSERT INTO external_role_mappings
              (tenant_id, source, external_role, group_id, mode, priority, is_active)
            VALUES
              ($1, 'ad', $2, $3, $4, $5, true)
            ON CONFLICT (tenant_id, source, external_role, group_id, mode)
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
        .bind(mode)
        .bind(priority)
        .execute(&mut *tx)
        .await;
        if result.is_ok() {
            created += 1;
        }
    }

    if let Err(e) = tx.commit().await {
        return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}")).into_response();
    }

    if let Err(err) = oauth2::sync_ldap_roles_force(state.oauth_state.as_ref(), &user, &user.email).await {
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
            "/admin/ui/users",
            "error",
            &format!("Mappings saved ({created}), but sync failed: {err}"),
        )
        .into_response();
    }

    simple_idm_core::audit::emit_event(
        &state.db_pool,
        "ad.role_mapping.apply",
        "external_role_mappings",
        Some(user.id),
        "success",
        Some(json!({"count": created})),
    )
    .await;

    redirect_with(
        "/admin/ui/users",
        "message",
        &format!("AD mappings applied: {created}"),
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

    if state.oauth_state.ldap_auth.is_none() {
        return redirect_with("/admin/ui/users", "error", "AD auth is not enabled").into_response();
    }

    let user_exists = match sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_one(&state.db_pool)
    .await
    {
        Ok(v) => v > 0,
        Err(e) => {
            return redirect_with("/admin/ui/users", "error", &format!("DB error: {e}"))
                .into_response()
        }
    };
    if !user_exists {
        return redirect_with("/admin/ui/users", "error", "User not found").into_response();
    }

    let raw_token = random_onboarding_token();
    let token_hash = onboarding_token_hash(&raw_token);
    let expires_at = Utc::now() + chrono::Duration::seconds(state.ad_onboarding_token_ttl_seconds);

    let result = sqlx::query(
        r#"
        INSERT INTO ad_onboarding_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            let link = format!("/ad/onboarding?token={}", urlencoding::encode(&raw_token));
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
                "/admin/ui/users?message={}&ad_link={}",
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
                "/admin/ui/users",
                "error",
                &format!("Failed to generate onboarding link: {e}"),
            )
            .into_response()
        }
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

    render_template(GroupsTemplate {
        sections: nav_items(AdminSection::Groups),
        message: query.message,
        error: query.error,
        rows,
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

    let result = sqlx::query(r#"INSERT INTO groups (name, description, is_virtual) VALUES ($1, $2, $3)"#)
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

    let result = sqlx::query(r#"UPDATE groups SET name=$2, description=$3, is_virtual=$4 WHERE id=$1"#)
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

async fn groups_deactivate(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let result = sqlx::query(
        r#"UPDATE groups SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/groups", "message", "Group deactivated (safe delete)")
            .into_response(),
        Err(e) => redirect_with("/admin/ui/groups", "error", &format!("Deactivate failed: {e}"))
            .into_response(),
    }
}

async fn user_groups_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, UserGroupRow>(
        r#"SELECT u.username, u.email, g.name AS group_name
           FROM user_groups ug
           JOIN users u ON u.id = ug.user_id
           JOIN groups g ON g.id = ug.group_id
           WHERE u.deleted_at IS NULL AND g.deleted_at IS NULL
           ORDER BY u.username, g.name"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/user-groups", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    render_template(UserGroupsTemplate {
        sections: nav_items(AdminSection::UserGroups),
        message: query.message,
        error: query.error,
        rows,
    })
}

async fn group_users_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, UserGroupRow>(
        r#"SELECT u.username, u.email, g.name AS group_name
           FROM user_groups ug
           JOIN users u ON u.id = ug.user_id
           JOIN groups g ON g.id = ug.group_id
           WHERE u.deleted_at IS NULL AND g.deleted_at IS NULL
           ORDER BY g.name, u.username"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/group-users", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in rows {
        grouped
            .entry(r.group_name)
            .or_default()
            .push(format!("{} <{}>", r.username, r.email));
    }

    let rows = grouped
        .into_iter()
        .map(|(group_name, users)| GroupUsersRow {
            group_name,
            users: users.join(", "),
        })
        .collect::<Vec<_>>();

    render_template(GroupUsersTemplate {
        sections: nav_items(AdminSection::GroupUsers),
        message: query.message,
        error: query.error,
        rows,
    })
}

async fn clients_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, ClientRow>(
        r#"SELECT id, client_id, name, redirect_uris, grant_types, scope, is_active, is_public
           FROM oauth_clients WHERE deleted_at IS NULL ORDER BY name ASC"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/clients", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    render_template(ClientsTemplate {
        sections: nav_items(AdminSection::Clients),
        message: query.message,
        error: query.error,
        rows,
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

    let is_public = parse_checkbox(&form.is_public);
    let is_active = parse_checkbox(&form.is_active);
    let client_secret_hash = if is_public {
        None
    } else {
        match simple_idm_core::auth::password::hash_password("change-me") {
            Ok(v) => Some(v),
            Err(e) => {
                return redirect_with("/admin/ui/clients", "error", &format!("Hash failed: {e}"))
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
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5, $6, $7, $8, 'effective', true, false)"#,
    )
    .bind(form.client_id.trim())
    .bind(client_secret_hash)
    .bind(form.name.trim())
    .bind(split_csv(&form.redirect_uris))
    .bind(grants)
    .bind(scopes)
    .bind(is_active)
    .bind(is_public)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/clients", "message", "Client created").into_response(),
        Err(e) => redirect_with("/admin/ui/clients", "error", &format!("Create failed: {e}"))
            .into_response(),
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

    let is_active = parse_checkbox(&form.is_active);

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
        r#"UPDATE oauth_clients
           SET client_id=$2, name=$3, redirect_uris=$4, grant_types=$5, scope=$6, is_active=$7, updated_at=NOW()
           WHERE id=$1"#,
    )
    .bind(id)
    .bind(form.client_id.trim())
    .bind(form.name.trim())
    .bind(split_csv(&form.redirect_uris))
    .bind(grants)
    .bind(scopes)
    .bind(is_active)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/clients", "message", "Client updated").into_response(),
        Err(e) => redirect_with("/admin/ui/clients", "error", &format!("Update failed: {e}"))
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

    let result = sqlx::query(
        r#"UPDATE oauth_clients SET is_active=false, updated_at=NOW() WHERE id=$1"#,
    )
    .bind(id)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/clients", "message", "Client deactivated (safe delete)")
            .into_response(),
        Err(e) => redirect_with("/admin/ui/clients", "error", &format!("Deactivate failed: {e}"))
            .into_response(),
    }
}

async fn client_claims_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, ClaimMapRow>(
        r#"SELECT oc.name AS client_name,
                  g.name AS group_name,
                  cm.claim_name,
                  cm.claim_value,
                  cm.claim_value_kind
           FROM claim_maps cm
           JOIN oauth_clients oc ON oc.id = cm.client_id
           LEFT JOIN groups g ON g.id = cm.group_id
           WHERE cm.deleted_at IS NULL
             AND oc.deleted_at IS NULL
             AND (g.id IS NULL OR g.deleted_at IS NULL)
           ORDER BY oc.name, cm.claim_name"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/client-claims", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let mut client_claims: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        let claim_value = row
            .claim_value
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string());
        client_claims.entry(row.client_name).or_default().push(format!(
            "{}={} ({}, group={})",
            row.claim_name,
            claim_value,
            row.claim_value_kind,
            row.group_name.unwrap_or_else(|| "*".to_string())
        ));
    }

    let rows = client_claims
        .into_iter()
        .map(|(client_name, claims)| ClientClaimsRow {
            client_name,
            claims: claims.join(" | "),
        })
        .collect::<Vec<_>>();

    let clients = sqlx::query_as::<_, (Uuid, String)>("SELECT id, name FROM oauth_clients WHERE deleted_at IS NULL ORDER BY name")
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();
    let groups = sqlx::query_as::<_, (Uuid, String)>("SELECT id, name FROM groups WHERE deleted_at IS NULL ORDER BY name")
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();

    render_template(ClientClaimsTemplate {
        sections: nav_items(AdminSection::ClientClaims),
        message: query.message,
        error: query.error,
        rows,
        clients,
        groups,
    })
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
        Err(_) => return redirect_with("/admin/ui/client-claims", "error", "Invalid client_id").into_response(),
    };

    let group_id = form
        .group_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| Uuid::parse_str(v).ok());

    let claim_value_json = if form.claim_value_kind == "array" {
        serde_json::json!(split_csv(&form.claim_value))
    } else {
        serde_json::json!(form.claim_value.trim())
    };

    let result = sqlx::query(
        r#"INSERT INTO claim_maps (tenant_id, client_id, group_id, claim_name, claim_value, claim_value_kind)
           VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, $3, $4, $5::claim_value_kind)"#,
    )
    .bind(client_id)
    .bind(group_id)
    .bind(form.claim_name.trim())
    .bind(claim_value_json)
    .bind(form.claim_value_kind.trim())
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => redirect_with("/admin/ui/client-claims", "message", "Claim map created").into_response(),
        Err(e) => redirect_with("/admin/ui/client-claims", "error", &format!("Create failed: {e}"))
            .into_response(),
    }
}

async fn group_claims_page(
    State(state): State<WebAdminState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(redir) = require_admin_token(&state, &headers).await {
        return redir.into_response();
    }

    let rows = match sqlx::query_as::<_, ClaimMapRow>(
        r#"SELECT oc.name AS client_name,
                  g.name AS group_name,
                  cm.claim_name,
                  cm.claim_value,
                  cm.claim_value_kind
           FROM claim_maps cm
           JOIN oauth_clients oc ON oc.id = cm.client_id
           LEFT JOIN groups g ON g.id = cm.group_id
           WHERE cm.deleted_at IS NULL
             AND oc.deleted_at IS NULL
             AND (g.id IS NULL OR g.deleted_at IS NULL)
           ORDER BY g.name NULLS LAST, oc.name, cm.claim_name"#,
    )
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return redirect_with("/admin/ui/group-claims", "error", &format!("DB error: {e}"))
                .into_response();
        }
    };

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        let g = row.group_name.unwrap_or_else(|| "*".to_string());
        let claim_value = row
            .claim_value
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string());
        grouped.entry(g).or_default().push(format!(
            "{}: {}={} ({})",
            row.client_name, row.claim_name, claim_value, row.claim_value_kind
        ));
    }

    let rows = grouped
        .into_iter()
        .map(|(group_name, claims)| GroupClaimsRow {
            group_name,
            claims: claims.join(" | "),
        })
        .collect::<Vec<_>>();

    render_template(GroupClaimsTemplate {
        sections: nav_items(AdminSection::GroupClaims),
        message: query.message,
        error: query.error,
        rows,
    })
}
