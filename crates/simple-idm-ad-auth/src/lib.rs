use anyhow::{anyhow, Context, Result};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum LdapTlsMode {
    Ldaps,
    StartTls,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LdapAuthConfig {
    pub host: String,
    pub port: u16,
    pub base_dn: String,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub user_filter: String,
    pub tls_mode: LdapTlsMode,
    pub timeout_seconds: u64,
    pub allow_insecure: bool,
}

impl LdapAuthConfig {
    pub fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            return Err(anyhow!("LDAP host is required"));
        }
        if self.base_dn.trim().is_empty() {
            return Err(anyhow!("LDAP base_dn is required"));
        }
        if self.user_filter.trim().is_empty() {
            return Err(anyhow!("LDAP user_filter is required"));
        }
        if self.timeout_seconds == 0 {
            return Err(anyhow!("LDAP timeout_seconds must be > 0"));
        }
        Ok(())
    }

    fn url(&self) -> String {
        match self.tls_mode {
            LdapTlsMode::Ldaps => format!("ldaps://{}:{}", self.host, self.port),
            LdapTlsMode::StartTls => format!("ldap://{}:{}", self.host, self.port),
        }
    }
}

/// Verify user credentials against LDAP/AD.
///
/// Behavior:
/// - If `bind_dn` is configured, it performs service bind + search by `user_filter` then user bind.
/// - If `bind_dn` is not configured, it attempts direct bind with `login` as DN/UPN.
pub async fn verify_ldap_password(
    cfg: &LdapAuthConfig,
    login: &str,
    password: &str,
) -> Result<()> {
    cfg.validate()?;

    if password.is_empty() {
        return Err(anyhow!("Password must not be empty"));
    }

    if cfg.allow_insecure {
        tracing::warn!("LDAP allow_insecure=true is not fully supported in MVP");
    }

    let url = cfg.url();
    let (conn, mut ldap) = LdapConnAsync::new(&url)
        .await
        .with_context(|| format!("Failed to connect to LDAP server: {}", url))?;
    ldap3::drive!(conn);

    match cfg.tls_mode {
        LdapTlsMode::Ldaps => {}
        LdapTlsMode::StartTls => {
            return Err(anyhow!(
                "StartTLS mode is not implemented in MVP; use LDAPS"
            ));
        }
    }

    if let Some(bind_dn) = cfg.bind_dn.as_deref() {
        let bind_password = cfg
            .bind_password
            .as_deref()
            .ok_or_else(|| anyhow!("LDAP bind_password is required when bind_dn is set"))?;

        ldap.simple_bind(bind_dn, bind_password)
            .await
            .context("LDAP service bind request failed")?
            .success()
            .context("LDAP service bind failed")?;

        let escaped_login = ldap3::ldap_escape(login);
        // Support both placeholders:
        // - {login} (simple-idm)
        // - {1}     (common Java LDAP templates)
        let filter = cfg
            .user_filter
            .replace("{login}", &escaped_login)
            .replace("{1}", &escaped_login);

        let (entries, _res) = ldap
            .search(&cfg.base_dn, Scope::Subtree, &filter, vec!["dn"])
            .await
            .with_context(|| format!("LDAP search request failed with filter: {}", filter))?
            .success()
            .context("LDAP search failed")?;

        let dn = entries
            .into_iter()
            .next()
            .map(SearchEntry::construct)
            .map(|e| e.dn)
            .ok_or_else(|| anyhow!("LDAP user not found"))?;

        ldap.simple_bind(&dn, password)
            .await
            .context("LDAP user bind request failed")?
            .success()
            .context("LDAP user bind failed")?;

        Ok(())
    } else {
        ldap.simple_bind(login, password)
            .await
            .context("LDAP direct bind request failed")?
            .success()
            .context("LDAP direct bind failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_config_validation_works() {
        let cfg = LdapAuthConfig {
            host: "ldap.example.com".to_string(),
            port: 636,
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: None,
            bind_password: None,
            user_filter: "(mail={login})".to_string(),
            tls_mode: LdapTlsMode::Ldaps,
            timeout_seconds: 5,
            allow_insecure: false,
        };

        assert!(cfg.validate().is_ok());
    }
}
