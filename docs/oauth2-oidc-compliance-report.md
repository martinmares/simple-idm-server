# OAuth2 a OpenID Connect Compliance Report

**Projekt:** simple-idm-server
**Datum:** 2026-01-24
**Verze:** v0.1.0-oauth2-complete
**Celkové Skóre:** ~75-80% RFC compliance

---

## Executive Summary

Simple IDM Server implementuje **klíčové OAuth2 a OpenID Connect funkcionality** s dobrými bezpečnostními základy, ale má **několik zásadních nedostatků** pro dosažení 100% RFC compliance.

### Implementované komponenty

- ✅ Authorization Code Grant Flow (RFC 6749 4.1)
- ✅ Refresh Token Flow s rotací
- ✅ Device Authorization Grant (RFC 8628)
- ✅ Client Credentials Flow
- ✅ Token Revocation (RFC 7009)
- ✅ Token Introspection (RFC 7662)
- ✅ PKCE (RFC 7636) - podpora S256 a plain
- ✅ OpenID Connect Discovery 1.0
- ✅ JWKS Endpoint
- ✅ UserInfo Endpoint
- ✅ SSO/Authentication Session Management

---

## Compliance Matrix - Shrnutí

| Standard | Coverage | Status |
|----------|----------|--------|
| RFC 6749 - OAuth 2.0 | ~85% | ⚠️ Téměř kompletní, chybí scope validation |
| RFC 8628 - Device Flow | ~90% | ✅ Dobrá, chybí slow_down error |
| OIDC Core 1.0 | ~75% | ⚠️ Běžné claims, chybí standard fields |
| RFC 7009 - Revocation | ~70% | ⚠️ Pouze refresh tokens, ne access |
| RFC 7662 - Introspection | ~90% | ✅ Dobrá implementace |
| RFC 7636 - PKCE | ~85% | ⚠️ Chybí length validation |
| Security Best Practices | ~60% | ⚠️ HTTPS enforcement, CSRF, brute force |

---

## 1. RFC 6749 - OAuth 2.0 Authorization Framework

### ✅ Implementované Features

#### Authorization Endpoint (`/oauth2/authorize`)
- ✅ `response_type` validation (pouze "code")
- ✅ `client_id` ověření
- ✅ `redirect_uri` validace (přesná shoda + loopback wildcard)
- ✅ `state` parameter podpora (RECOMMENDED)
- ✅ PKCE support (`code_challenge`, `code_challenge_method`)
- ✅ OIDC `nonce` parameter
- ✅ SSO session management (HttpOnly cookies, SameSite=Lax)

#### Token Endpoint (`/oauth2/token`)
- ✅ Grant types: `authorization_code`, `refresh_token`, `client_credentials`, `device_code`
- ✅ Strict redirect_uri validation (RFC 6749 section 4.1.3)
- ✅ PKCE validation (SHA256 + plain)
- ✅ Client authentication (`client_secret_post`, `client_secret_basic`)
- ✅ Token response: `access_token`, `token_type`, `expires_in`, `refresh_token`, `id_token`, `scope`

#### Refresh Token Flow
- ✅ Token rotation - nový refresh token při každé výměně
- ✅ Replay detection - tracking used_refresh_tokens
- ✅ Family-based revocation při detekci replay
- ✅ Expiry tracking

#### Authorization Code Security
- ✅ Expiry (10 minut)
- ✅ One-time use
- ✅ Client association
- ✅ User association

### ❌ Chybějící Features

#### Scope Validation
**Severity:** VYSOKÁ
**Soubor:** `src/oauth2/authorization_code.rs`

```rust
// PROBLÉM: Scopes se akceptují bez validace
let scope = params.get("scope").unwrap_or(&client.scope);
// Klient může požadovat libovolné scopes

// ŘEŠENÍ:
fn validate_scope(requested: &str, allowed: &str) -> Result<(), String> {
    for scope in requested.split_whitespace() {
        if !allowed.split_whitespace().contains(&scope) {
            return Err(format!("Invalid scope: {}", scope));
        }
    }
    Ok(())
}
```

#### Client Authentication Methods
- ❌ `client_secret_jwt` (RFC 7523)
- ❌ `private_key_jwt` (RFC 7523)
- ❌ `tls_client_auth` (RFC 8705)

#### Discovery Metadata
```json
// CHYBÍ v /.well-known/openid-configuration:
{
  "revocation_endpoint": "https://issuer/oauth2/revoke",
  "introspection_endpoint": "https://issuer/oauth2/introspect"
}
```

---

## 2. RFC 8628 - Device Authorization Grant

### ✅ Implementované Features

#### Device Authorization Endpoint (`/oauth2/device/authorize`)
- ✅ `client_id` validation
- ✅ `scope` parameter (OPTIONAL)
- ✅ Response: `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval`

**Configuration:**
```
- device_code: 64-char alphanumeric
- user_code: XXXX-XXXX format (8 chars)
- expiry: 600 seconds (10 minut)
- polling_interval: 5 seconds
```

#### Device Verification Endpoint (`/device`)
- ✅ User code validation
- ✅ Brute force protection (max 5 pokusů)
- ✅ Expiry check
- ✅ Username/password validation
- ✅ One-time authorization

#### Device Token Endpoint
- ✅ Grant type: `urn:ietf:params:oauth:grant-type:device_code`
- ✅ Error responses: `invalid_grant`, `expired_token`, `authorization_pending`
- ✅ HTTP 400 pro error responses (RFC 8628 compliance)

### ❌ Chybějící Features

#### Slow Down Error Handling
**Severity:** STŘEDNÍ

RFC 8628 Section 3.4 doporučuje `slow_down` error když klient polluje příliš rychle.

```rust
// DOPORUČENÍ: Rate limiting specifický pro device token endpoint
if polling_too_fast {
    return (StatusCode::BAD_REQUEST, Json(ErrorResponse {
        error: "slow_down".to_string(),
        error_description: "Slow down polling interval by 5 seconds".to_string(),
    }))
}
```

#### IP Extraction pro Logging
**Soubor:** `src/oauth2/device_flow.rs:290`

```rust
// TODO: Extract real IP from request
.bind("unknown")
```

---

## 3. OpenID Connect Core 1.0

### ✅ Implementované Features

#### Discovery Endpoint (`/.well-known/openid-configuration`)
- ✅ REQUIRED claims: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`
- ✅ RECOMMENDED claims: `scopes_supported`, `token_endpoint_auth_methods_supported`, `userinfo_endpoint`, `code_challenge_methods_supported`
- ✅ OPTIONAL claims: `claims_supported`, `device_authorization_endpoint`

#### ID Token
**REQUIRED Claims:**
- ✅ `iss` - Issuer
- ✅ `sub` - User ID (UUID)
- ✅ `aud` - Client ID
- ✅ `exp` - Expiration
- ✅ `iat` - Issued at

**OPTIONAL Claims:**
- ✅ `nonce` - OIDC nonce parameter
- ✅ `email` - User email
- ✅ `preferred_username` - Username
- ✅ `groups` - User groups

#### UserInfo Endpoint (`/oauth2/userinfo`)
- ✅ Bearer token authentication
- ✅ Scope-based claim revelation
  - `openid` → `sub` (vždy)
  - `email` → `email`
  - `profile` → `preferred_username`, name fields
  - `groups` → `groups`
- ✅ Error handling: `invalid_token`, `insufficient_scope`

### ❌ Chybějící Features

#### Standard OIDC Claims
**Severity:** STŘEDNÍ

Chybějící claims v ID tokenu a UserInfo:
- ❌ `auth_time` - Čas autentizace uživatele
- ❌ `acr` - Authentication Context Class Reference
- ❌ `name`, `given_name`, `family_name` - Jméno uživatele
- ❌ `email_verified` - Email verification flag
- ❌ `picture`, `locale` - Profil claims
- ❌ `phone_number`, `address` - Kontaktní informace

**Důvod:** Databázový model `User` obsahuje pouze `username` a `email`.

**Řešení:** Rozšířit tabulku `users`:
```sql
ALTER TABLE users ADD COLUMN given_name VARCHAR(100);
ALTER TABLE users ADD COLUMN family_name VARCHAR(100);
ALTER TABLE users ADD COLUMN picture_url VARCHAR(500);
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN phone_number VARCHAR(20);
ALTER TABLE users ADD COLUMN locale VARCHAR(10);
```

#### UserInfo POST Method
OIDC Core Section 5.3.1 doporučuje POST jako alternativu k GET pro bezpečnost.

```rust
// Přidat do src/main.rs:
.route("/oauth2/userinfo", post(oauth2::handle_userinfo_post))
```

---

## 4. RFC 7009 - Token Revocation

### ✅ Implementované Features

#### Revocation Endpoint (`/oauth2/revoke`)
- ✅ `token` parameter (REQUIRED)
- ✅ `token_type_hint` parameter (OPTIONAL)
- ✅ Client authentication (`client_id` + `client_secret`)
- ✅ HTTP Basic Auth i POST form support
- ✅ Vrací 200 OK bez ohledu na existenci tokenu (RFC 7009 Section 2.2)
- ✅ Transactionality: Insert into used_refresh_tokens + Delete

### ❌ Chybějící Features

#### Access Token Revocation
**Severity:** VYSOKÁ
**Soubor:** `src/oauth2/revocation.rs:110-117`

```rust
// PROBLÉM: Access tokeny se ignorují
if hint != "refresh_token" {
    return OK  // Podle spec, vracíme 200
}

// ŘEŠENÍ: Implementovat blacklist pro access tokeny
CREATE TABLE revoked_access_tokens (
    jti VARCHAR(100) PRIMARY KEY,  -- JWT ID claim
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP DEFAULT NOW()
);

// Index pro cleanup:
CREATE INDEX idx_revoked_access_tokens_expires
ON revoked_access_tokens(expires_at);
```

**Poznámka:** Bez blacklistu nelze access tokeny zneplatnit před expirací.

---

## 5. RFC 7662 - Token Introspection

### ✅ Implementované Features

#### Introspection Endpoint (`/oauth2/introspect`)
- ✅ `token` parameter (REQUIRED)
- ✅ `token_type_hint` parameter (OPTIONAL)
- ✅ Client authentication (REQUIRED)
- ✅ Response format pro active/inactive tokeny

**Active Token Response:**
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "client-id",
  "username": "john_doe",
  "sub": "user-uuid",
  "exp": 1234567890,
  "iat": 1234567800,
  "iss": "http://issuer",
  "aud": ["client-id"],
  "email": "john@example.com",
  "preferred_username": "john_doe"
}
```

### ⚠️ Poznámky

- Access token hint aktuálně vrací 404 "invalid" (mělo by podporovat)
- Chybí `id_token` hint support
- Bez audit logu pro introspection requesty

---

## 6. RFC 7636 - PKCE

### ✅ Implementované Features

**Soubor:** `src/oauth2/authorization_code.rs:800-836`

- ✅ `code_challenge` parameter
- ✅ `code_challenge_method` (S256, plain)
- ✅ SHA256 hashing s URL-safe base64 encoding
- ✅ Verifikace na token endpoint
- ✅ PKCE povinné pro public clients

```rust
match code_challenge_method {
    Some("plain") => challenge == verifier,
    Some("S256") => {
        let hash = Sha256::digest(verifier.as_bytes());
        let encoded = URL_SAFE_NO_PAD.encode(hash);
        challenge == &encoded
    }
    _ => false
}
```

### ❌ Chybějící Features

#### PKCE Length Validation
**Severity:** STŘEDNÍ

RFC 7636 Section 4.1 vyžaduje:
- `code_verifier` délka: 43-128 znaků

```rust
// ŘEŠENÍ:
if let Some(verifier) = &req.code_verifier {
    if verifier.len() < 43 || verifier.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "code_verifier must be 43-128 characters".to_string(),
            }),
        ).into_response();
    }
}
```

---

## 7. Security Best Practices

### ✅ Implementované Security Features

#### Redirect URI Validation
- ✅ Přesná shoda
- ✅ Loopback wildcard pattern (http://localhost:*/path)
- ✅ Fragment checking (RFC 6749 Section 3.1.2.1)

#### Client Authentication
- ✅ Argon2id password hashing (memory-hard)
- ✅ Constant-time comparison
- ✅ Public clients support

#### Token Security
- ✅ Authorization code expiry (10 minut)
- ✅ One-time use enforcement
- ✅ Refresh token rotation
- ✅ Replay detection

#### Rate Limiting
- ✅ Globální: 5 RPS, burst 10
- ✅ Token endpoint: 2 RPS, burst 5 (přísnější)
- ✅ IP-based extraction

#### Session Management
- ✅ HttpOnly cookies
- ✅ SameSite=Lax
- ✅ Session expiry tracking

### ❌ Kritické Bezpečnostní Nedostatky

#### 1. HTTPS Enforcement
**Severity:** KRITICKÁ
**Soubor:** `src/main.rs`

```rust
// ŘEŠENÍ:
fn main() {
    // ...
    if cfg!(not(debug_assertions)) {
        if !config.jwt.issuer.starts_with("https://") {
            panic!("HTTPS is REQUIRED in production! (RFC 6749 Section 1.6)");
        }
    }
}
```

**RFC 6749 Section 1.6 VYŽADUJE HTTPS** v produkci!

#### 2. Secure Cookie Flags
**Severity:** VYSOKÁ

```rust
// AKTUÁLNĚ: SameSite=Lax
// DOPORUČENÍ:
Cookie::build("auth_session", session_id)
    .http_only(true)
    .secure(!cfg!(debug_assertions))  // true v produkci
    .same_site(SameSite::Strict)      // Strict místo Lax
    .path("/")
    .finish()
```

#### 3. CSRF Protection
**Severity:** VYSOKÁ

POST endpointy (`/oauth2/login`, `/device/verify`) nejsou chráněny proti CSRF.

```rust
// ŘEŠENÍ: Generovat CSRF token
fn generate_csrf_token() -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

// Validovat při POST
if csrf_token != session.csrf_token {
    return error("invalid_csrf_token");
}
```

#### 4. Brute Force Protection
**Severity:** VYSOKÁ
**Soubor:** `src/oauth2/authorization_code.rs`

Login endpoint (`/oauth2/login`) nemá rate limiting na počet pokusů.

```rust
// ŘEŠENÍ: Tracking failed logins
CREATE TABLE login_attempts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    ip_address VARCHAR(45),
    failed_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_username_ip (username, ip_address, failed_at)
);

// Před autentizací:
let failures = sqlx::query_scalar!(
    "SELECT COUNT(*) FROM login_attempts
     WHERE (username = $1 OR ip_address = $2)
     AND failed_at > NOW() - INTERVAL '15 minutes'",
    username, ip_address
).fetch_one(&pool).await?;

if failures >= 5 {
    return error("too_many_attempts");
}
```

#### 5. Security Headers
**Severity:** STŘEDNÍ

```rust
// Přidat middleware do src/main.rs:
use tower_http::set_header::SetResponseHeaderLayer;

.layer(SetResponseHeaderLayer::overriding(
    header::STRICT_TRANSPORT_SECURITY,
    HeaderValue::from_static("max-age=31536000; includeSubDomains"),
))
.layer(SetResponseHeaderLayer::overriding(
    header::CONTENT_SECURITY_POLICY,
    HeaderValue::from_static("default-src 'self'"),
))
.layer(SetResponseHeaderLayer::overriding(
    HeaderValue::from_static("X-Content-Type-Options"),
    HeaderValue::from_static("nosniff"),
))
.layer(SetResponseHeaderLayer::overriding(
    HeaderValue::from_static("X-Frame-Options"),
    HeaderValue::from_static("DENY"),
))
```

#### 6. Password Policy
**Severity:** STŘEDNÍ

Aktuálně není žádná password policy.

```rust
// DOPORUČENÍ:
fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 12 {
        return Err("Password must be at least 12 characters".to_string());
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !(has_uppercase && has_lowercase && has_digit && has_special) {
        return Err("Password must contain uppercase, lowercase, digit, and special character".to_string());
    }

    // TODO: Check against common passwords (haveibeenpwned API)

    Ok(())
}
```

---

## 8. Prioritizace Oprav

### Phase 1 - Kritické bezpečnostní opravy (1-2 týdny)

| # | Oprava | Severity | Effort | Soubor |
|---|--------|----------|--------|--------|
| 1 | HTTPS enforcement | KRITICKÁ | 30 min | `src/main.rs` |
| 2 | Scope validation | VYSOKÁ | 1 hod | `src/oauth2/authorization_code.rs` |
| 3 | Brute force protection | VYSOKÁ | 2 hod | `src/oauth2/authorization_code.rs` |
| 4 | PKCE length validation | STŘEDNÍ | 20 min | `src/oauth2/authorization_code.rs` |
| 5 | Discovery metadata | STŘEDNÍ | 30 min | `src/oidc/mod.rs` |

### Phase 2 - RFC doplnění (2-4 týdny)

- [ ] Access token revocation (blacklist)
- [ ] Slow_down error v device flow
- [ ] POST method na /oauth2/userinfo
- [ ] Security headers middleware
- [ ] CSRF protection
- [ ] Secure cookie flags

### Phase 3 - OIDC rozšíření (1 měsíc)

- [ ] Standard claims (name, family_name, picture, email_verified)
- [ ] auth_time, acr claims
- [ ] Email verification tracking
- [ ] Password policy enforcement
- [ ] Audit logging

### Phase 4 - Advanced features (2-3 měsíce)

- [ ] Front-channel logout (RFC 9386)
- [ ] Dynamic Client Registration (RFC 7591)
- [ ] JWT client authentication (RFC 7523)
- [ ] Pushed Authorization Requests (RFC 9126)
- [ ] Token binding (RFC 8471)
- [ ] MTLS support (RFC 8705)

---

## 9. Doporučení pro Produkční Nasazení

### Před nasazením do produkce MUSÍ být opraveno:

1. ✅ **HTTPS enforcement** - Přidat kontrolu v main()
2. ✅ **Scope validation** - Validovat requested scopes
3. ✅ **Brute force protection** - Rate limiting na login
4. ✅ **Security headers** - HSTS, CSP, X-Frame-Options
5. ✅ **Secure cookies** - Secure flag v produkci

### Konfigurace RUST_LOG pro produkci:

```bash
RUST_LOG=simple_idm_server=info,tower_http=info
```

Pro debugging:
```bash
RUST_LOG=simple_idm_server::oauth2::device_flow=debug
```

---

## 10. Závěr

Simple IDM Server je **solidní OAuth2/OIDC implementace** s ~75-80% RFC compliance.

**Vhodný pro:**
- ✅ Interní corporate SSO
- ✅ Development/test environments
- ✅ Trusted clients (vlastní aplikace)

**Vyžaduje dodatečnou práci pro:**
- ❌ Public-facing deployment bez Phase 1 oprav
- ❌ Strict RFC compliance (100%)
- ❌ Enterprise-grade features

**Doporučená akce:** Implementovat Phase 1 kritické opravy jako prerequisite pro production deployment.

---

**Report vygenerován:** 2026-01-24
**Autor:** Claude Sonnet 4.5 + Martin Mareš
**Verze projektu:** v0.1.0-oauth2-complete
