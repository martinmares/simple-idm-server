use anyhow::{Result, bail};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct AuthPolicy {
    pub mfa_policy: String,
    pub passkey_policy: String,
}

impl AuthPolicy {
    pub fn accepts_session(&self, amr: &[String]) -> bool {
        let passkey = amr.iter().any(|method| method == "webauthn");
        if passkey && self.passkey_policy != "allowed" {
            return false;
        }
        self.mfa_policy != "required"
            || amr
                .iter()
                .any(|method| matches!(method.as_str(), "otp" | "recovery" | "webauthn"))
    }
}

pub async fn for_user(pool: &PgPool, user_id: Uuid) -> Result<AuthPolicy> {
    Ok(sqlx::query_as(
        "SELECT mfa_policy, passkey_policy FROM effective_user_auth_policies WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?)
}

pub async fn accepts_authentication(
    pool: &PgPool,
    user: &crate::db::models::User,
    amr: &[String],
) -> Result<bool> {
    let policy = for_user(pool, user.id).await?;
    Ok(!user.auth_mode.eq_ignore_ascii_case("local") || policy.accepts_session(amr))
}

pub fn validate_domain_overrides(mfa: &str, passkeys: &str) -> Result<()> {
    if !matches!(mfa, "inherit" | "disabled" | "optional" | "required") {
        bail!("Domain MFA policy must be inherit, disabled, optional or required");
    }
    if !matches!(passkeys, "inherit" | "disabled" | "allowed") {
        bail!("Domain passkey policy must be inherit, disabled or allowed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires disposable DOMAIN_POLICY_TEST_DATABASE_URL"]
    async fn postgres_domain_authentication_rules() {
        let pool = PgPool::connect(&std::env::var("DOMAIN_POLICY_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        sqlx::migrate::Migrator::new(migrations)
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        let tenant = Uuid::new_v4();
        let foreign_tenant = Uuid::new_v4();
        let domain = format!("{}.auth.test", tenant.simple());
        let local_domain = format!("{}.local.test", tenant.simple());
        for id in [tenant, foreign_tenant] {
            sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'Auth rule test')")
                .bind(id)
                .bind(id.to_string())
                .execute(&pool)
                .await
                .unwrap();
        }
        let mut providers = Vec::new();
        for (owner, slug, kind) in [
            (tenant, "google", "google"),
            (tenant, "other", "oidc"),
            (tenant, "ad", "ad_ldap"),
            (foreign_tenant, "foreign", "google"),
        ] {
            let id: Uuid = sqlx::query_scalar("INSERT INTO identity_providers (tenant_id, slug, provider_type, issuer, client_id, client_secret_encrypted) VALUES ($1,$2,$3,$2,$2,'test') RETURNING id")
                .bind(owner).bind(slug).bind(kind).fetch_one(&pool).await.unwrap();
            providers.push(id);
        }
        sqlx::query("INSERT INTO tenant_domains (tenant_id, domain, authentication_policy) VALUES ($1,$2,'local')")
            .bind(tenant).bind(&local_domain).execute(&pool).await.unwrap();
        let local_user: Uuid = sqlx::query_scalar(
            "INSERT INTO users (tenant_id,username,email) VALUES ($1,'local',$2) RETURNING id",
        )
        .bind(tenant)
        .bind(format!("alice@{local_domain}"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            sqlx::query("UPDATE users SET auth_mode='federated', auth_provider_id=$2 WHERE id=$1")
                .bind(local_user)
                .bind(providers[0])
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(sqlx::query("UPDATE tenant_domains SET authentication_policy='federated', auth_provider_id=$2 WHERE tenant_id=$1")
            .bind(tenant).bind(providers[0]).execute(&pool).await.is_err());
        for provider in [providers[2], providers[3]] {
            assert!(sqlx::query("INSERT INTO tenant_domains (tenant_id,domain,authentication_policy,auth_provider_id) VALUES ($1,$2,'federated',$3)")
                .bind(tenant).bind(&domain).bind(provider).execute(&pool).await.is_err());
        }
        sqlx::query("INSERT INTO tenant_domains (tenant_id,domain,authentication_policy,auth_provider_id) VALUES ($1,$2,'federated',$3)")
            .bind(tenant).bind(&domain).bind(providers[0]).execute(&pool).await.unwrap();
        assert!(
            sqlx::query("UPDATE users SET email=$2 WHERE id=$1")
                .bind(local_user)
                .bind(format!("alice@{domain}"))
                .execute(&pool)
                .await
                .is_err()
        );
        for mode in ["local", "ad"] {
            assert!(
                sqlx::query(
                    "INSERT INTO users (tenant_id,username,email,auth_mode) VALUES ($1,$2,$3,$2)"
                )
                .bind(tenant)
                .bind(mode)
                .bind(format!("{mode}@{domain}"))
                .execute(&pool)
                .await
                .is_err()
            );
        }
        assert!(sqlx::query("INSERT INTO users (tenant_id,username,email,auth_mode,auth_provider_id) VALUES ($1,'wrong',$2,'federated',$3)")
            .bind(tenant).bind(format!("wrong@{domain}")).bind(providers[1]).execute(&pool).await.is_err());
        let user: Uuid = sqlx::query_scalar("INSERT INTO users (tenant_id,username,email,auth_mode,auth_provider_id) VALUES ($1,'correct',$2,'federated',$3) RETURNING id")
            .bind(tenant).bind(format!("correct@{domain}").to_uppercase()).bind(providers[0]).fetch_one(&pool).await.unwrap();
        assert!(for_user(&pool, user).await.is_ok());
        sqlx::query("UPDATE identity_providers SET is_active=false WHERE id=$1")
            .bind(providers[0])
            .execute(&pool)
            .await
            .unwrap();
        assert!(for_user(&pool, user).await.is_err());
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT domain_authentication_allowed($1,$2,'federated',$3)"
            )
            .bind(tenant)
            .bind(format!("new@{domain}"))
            .bind(providers[0])
            .fetch_one(&pool)
            .await
            .unwrap()
                == false
        );
        sqlx::query("UPDATE tenant_domains SET is_active=false WHERE domain=$1")
            .bind(&domain)
            .execute(&pool)
            .await
            .unwrap();
        assert!(for_user(&pool, user).await.is_ok());
        assert!(
            sqlx::query("UPDATE tenant_domains SET is_active=true WHERE domain=$1")
                .bind(&domain)
                .execute(&pool)
                .await
                .is_err()
        );
        sqlx::query("UPDATE identity_providers SET is_active=true WHERE id=$1")
            .bind(providers[0])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE tenant_domains SET is_active=true WHERE domain=$1")
            .bind(&domain)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET deleted_at=NOW() WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE tenant_domains SET authentication_policy='ad',auth_provider_id=$2 WHERE domain=$1")
            .bind(&domain).bind(providers[2]).execute(&pool).await.unwrap();
        assert!(
            sqlx::query("UPDATE users SET deleted_at=NULL WHERE id=$1")
                .bind(user)
                .execute(&pool)
                .await
                .is_err()
        );
        sqlx::query("INSERT INTO users (tenant_id,username,email,auth_mode,auth_provider_id) VALUES ($1,'ad',$2,'ad',$3)")
            .bind(tenant).bind(format!("ad@{domain}")).bind(providers[2]).execute(&pool).await.unwrap();

        let racing_domain = format!("{}.race.test", tenant.simple());
        sqlx::query("INSERT INTO tenant_domains (tenant_id,domain) VALUES ($1,$2)")
            .bind(tenant)
            .bind(&racing_domain)
            .execute(&pool)
            .await
            .unwrap();
        let mut assignment = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO users (tenant_id,username,email) VALUES ($1,'racing',$2)")
            .bind(tenant)
            .bind(format!("racing@{racing_domain}"))
            .execute(&mut *assignment)
            .await
            .unwrap();
        let other_pool = pool.clone();
        let changing_domain = racing_domain.clone();
        let provider = providers[0];
        let policy_change = tokio::spawn(async move {
            sqlx::query("UPDATE tenant_domains SET authentication_policy='federated',auth_provider_id=$2 WHERE domain=$1")
                .bind(changing_domain).bind(provider).execute(&other_pool).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!policy_change.is_finished());
        assignment.commit().await.unwrap();
        assert!(policy_change.await.unwrap().is_err());
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires disposable DOMAIN_POLICY_TEST_DATABASE_URL"]
    async fn postgres_domain_overrides_and_sessions() {
        let url = std::env::var("DOMAIN_POLICY_TEST_DATABASE_URL").unwrap();
        let pool = PgPool::connect(&url).await.unwrap();
        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        sqlx::migrate::Migrator::new(migrations)
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let suffix = tenant.simple().to_string();
        let cloud = format!("{suffix}.cloud.test");
        let other = format!("{suffix}.cz.test");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'Domain policies')")
            .bind(tenant)
            .bind(&suffix)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO tenant_domains (tenant_id, domain, mfa_policy, passkey_policy) VALUES ($1, $2, 'required', 'allowed'), ($1, $3, 'inherit', 'inherit')")
            .bind(tenant).bind(&cloud).bind(&other).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id, tenant_id, username, email, password_hash) VALUES ($1, $2, $3, $4, 'test-hash')")
            .bind(user).bind(tenant).bind(&suffix).bind(format!("alice@{cloud}").to_uppercase())
            .execute(&pool).await.unwrap();
        let policy = for_user(&pool, user).await.unwrap();
        assert_eq!(policy.mfa_policy, "required");
        assert_eq!(policy.passkey_policy, "allowed");
        assert_eq!(
            crate::mfa::user_mfa_policy(&pool, user).await.unwrap(),
            crate::mfa::MfaPolicy::Required
        );
        let service = crate::passkeys::PasskeyService::new(&crate::config::WebauthnConfig {
            rp_id: "localhost".into(),
            rp_name: "Policy test".into(),
            origins: vec!["http://localhost:8080".into()],
        })
        .unwrap();
        assert!(
            service
                .start_registration(&pool, tenant, user, "Alice", "Alice")
                .await
                .is_ok()
        );
        sqlx::query("INSERT INTO authentication_sessions (session_token, user_id, expires_at, amr) VALUES ($1, $2, NOW() + interval '1 hour', ARRAY['pwd'])")
            .bind(&suffix).bind(user).execute(&pool).await.unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("auth_session={suffix}").parse().unwrap(),
        );
        assert!(
            crate::oauth2::authorization_code::get_auth_session_from_cookie(&pool, &headers)
                .await
                .is_none()
        );
        sqlx::query(
            "UPDATE authentication_sessions SET amr = ARRAY['pwd', 'otp'] WHERE session_token = $1",
        )
        .bind(&suffix)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            crate::oauth2::authorization_code::get_auth_session_from_cookie(&pool, &headers)
                .await
                .is_some()
        );

        sqlx::query("UPDATE users SET email = $2 WHERE id = $1")
            .bind(user)
            .bind(format!("alice@{other}"))
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(for_user(&pool, user).await.unwrap().mfa_policy, "disabled");
        assert!(
            service
                .start_registration(&pool, tenant, user, "Alice", "Alice")
                .await
                .is_err()
        );
        sqlx::query(
            "UPDATE tenants SET mfa_policy = 'required', passkey_policy = 'allowed' WHERE id = $1",
        )
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(for_user(&pool, user).await.unwrap().mfa_policy, "required");
        sqlx::query("UPDATE tenant_domains SET mfa_policy = 'disabled', passkey_policy = 'disabled' WHERE tenant_id = $1 AND domain = $2")
            .bind(tenant).bind(&other).execute(&pool).await.unwrap();
        assert_eq!(for_user(&pool, user).await.unwrap().mfa_policy, "disabled");
        sqlx::query(
            "UPDATE authentication_sessions SET amr = ARRAY['webauthn'] WHERE session_token = $1",
        )
        .bind(&suffix)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            crate::oauth2::authorization_code::get_auth_session_from_cookie(&pool, &headers)
                .await
                .is_none()
        );
        sqlx::query(
            "UPDATE users SET auth_mode = 'federated', password_disabled = true WHERE id = $1",
        )
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            crate::oauth2::authorization_code::get_auth_session_from_cookie(&pool, &headers)
                .await
                .is_none()
        );
        sqlx::query("INSERT INTO authentication_sessions (session_token, user_id, expires_at, amr, credential_version) SELECT $1, id, NOW() + INTERVAL '1 hour', ARRAY['federated'], credential_version FROM users WHERE id = $2")
            .bind(&suffix).bind(user).execute(&pool).await.unwrap();
        assert!(
            crate::oauth2::authorization_code::get_auth_session_from_cookie(&pool, &headers)
                .await
                .is_some()
        );
        assert!(
            service
                .start_registration(&pool, tenant, user, "Alice", "Alice")
                .await
                .is_err()
        );
        sqlx::query(
            "UPDATE tenant_domains SET is_active = false WHERE tenant_id = $1 AND domain = $2",
        )
        .bind(tenant)
        .bind(&other)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(for_user(&pool, user).await.unwrap().mfa_policy, "required");
        sqlx::query("UPDATE tenant_domains SET is_active = true, deleted_at = NOW() WHERE tenant_id = $1 AND domain = $2")
            .bind(tenant).bind(&other).execute(&pool).await.unwrap();
        assert_eq!(
            for_user(&pool, user).await.unwrap().passkey_policy,
            "allowed"
        );
        sqlx::query("UPDATE users SET email = 'alice@unmanaged.test' WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(for_user(&pool, user).await.unwrap().mfa_policy, "required");
        sqlx::query("UPDATE tenants SET is_active = false WHERE id = $1")
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
        assert!(for_user(&pool, user).await.is_err());
        assert!(
            crate::oauth2::authorization_code::get_auth_session_from_cookie(&pool, &headers)
                .await
                .is_none()
        );
        pool.close().await;
    }

    #[test]
    fn validates_explicit_disabled_and_inheritance() {
        for mfa in ["inherit", "disabled", "optional", "required"] {
            for passkeys in ["inherit", "disabled", "allowed"] {
                assert!(validate_domain_overrides(mfa, passkeys).is_ok());
            }
        }
        assert!(validate_domain_overrides("unknown", "allowed").is_err());
        assert!(validate_domain_overrides("required", "required").is_err());
    }

    #[test]
    fn policy_changes_invalidate_inadequate_sessions() {
        let policy = AuthPolicy {
            mfa_policy: "required".into(),
            passkey_policy: "allowed".into(),
        };
        assert!(!policy.accepts_session(&["pwd".into()]));
        for method in ["otp", "recovery", "webauthn"] {
            assert!(policy.accepts_session(&[method.into()]));
        }
        let disabled = AuthPolicy {
            mfa_policy: "disabled".into(),
            passkey_policy: "disabled".into(),
        };
        assert!(!disabled.accepts_session(&["webauthn".into()]));
        assert!(disabled.accepts_session(&["pwd".into()]));
    }
}
