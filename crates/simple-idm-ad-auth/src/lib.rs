use anyhow::{Context, Result, anyhow};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LdapUserProfile {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub recovery_email: Option<String>,
    pub phone_e164: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LdapExternalIdentity {
    pub external_user_id: Option<String>,
    pub external_user_id_type: Option<String>,
    pub login_name: Option<String>,
    pub upn: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LdapUserData {
    pub roles: Vec<String>,
    pub profile: LdapUserProfile,
    pub identity: LdapExternalIdentity,
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
pub async fn verify_ldap_password(cfg: &LdapAuthConfig, login: &str, password: &str) -> Result<()> {
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

async fn connect_and_bind_service(cfg: &LdapAuthConfig) -> Result<ldap3::Ldap> {
    cfg.validate()?;

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

    let bind_dn = cfg
        .bind_dn
        .as_deref()
        .ok_or_else(|| anyhow!("LDAP bind_dn is required for role sync"))?;
    let bind_password = cfg
        .bind_password
        .as_deref()
        .ok_or_else(|| anyhow!("LDAP bind_password is required for role sync"))?;

    ldap.simple_bind(bind_dn, bind_password)
        .await
        .context("LDAP service bind request failed")?
        .success()
        .context("LDAP service bind failed")?;

    Ok(ldap)
}

async fn find_user_dn(ldap: &mut ldap3::Ldap, cfg: &LdapAuthConfig, login: &str) -> Result<String> {
    let escaped_login = ldap3::ldap_escape(login);
    let filter = cfg
        .user_filter
        .replace("{login}", &escaped_login)
        .replace("{1}", &escaped_login);

    let (entries, _res) = ldap
        .search(
            &cfg.base_dn,
            Scope::Subtree,
            &filter,
            vec!["dn", "memberOf"],
        )
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

    Ok(dn)
}

fn first_attr(se: &SearchEntry, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(vals) = se.attrs.get(*name)
            && let Some(first) = vals.first()
        {
            let v = first.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn format_ad_object_guid(raw: &[u8]) -> Option<String> {
    if raw.len() != 16 {
        return None;
    }
    let d1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let d2 = u16::from_le_bytes([raw[4], raw[5]]);
    let d3 = u16::from_le_bytes([raw[6], raw[7]]);
    let d4 = &raw[8..16];
    Some(format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    ))
}

/// Fetch AD/LDAP profile attributes + direct roles for `login`.
///
/// Uses service bind (`bind_dn` + `bind_password`).
pub async fn fetch_ldap_user_data(cfg: &LdapAuthConfig, login: &str) -> Result<LdapUserData> {
    let mut ldap = connect_and_bind_service(cfg).await?;
    let user_dn = find_user_dn(&mut ldap, cfg, login).await?;

    let escaped_dn = ldap3::ldap_escape(&user_dn);
    let user_dn_filter = format!("(distinguishedName={})", escaped_dn);

    let (entries, _res) = ldap
        .search(
            &cfg.base_dn,
            Scope::Subtree,
            &user_dn_filter,
            vec![
                "memberOf",
                "givenName",
                "sn",
                "mail",
                "otherMailbox",
                "mobile",
                "telephoneNumber",
                "sAMAccountName",
                "userPrincipalName",
                "objectGUID",
            ],
        )
        .await
        .with_context(|| format!("LDAP user data search failed for DN: {}", user_dn))?
        .success()
        .context("LDAP user data search failed")?;

    let mut roles = BTreeSet::new();
    let mut profile = LdapUserProfile::default();
    let mut identity = LdapExternalIdentity::default();

    if let Some(entry) = entries.into_iter().next() {
        let se = SearchEntry::construct(entry);
        if let Some(vals) = se.attrs.get("memberOf") {
            for v in vals {
                let s = v.trim();
                if !s.is_empty() {
                    roles.insert(s.to_string());
                }
            }
        }

        profile.first_name = first_attr(&se, &["givenName"]);
        profile.last_name = first_attr(&se, &["sn"]);
        profile.recovery_email = first_attr(&se, &["otherMailbox", "mail"]);
        profile.phone_e164 = first_attr(&se, &["mobile", "telephoneNumber"]);

        identity.login_name = first_attr(&se, &["sAMAccountName", "uid"]);
        identity.upn = first_attr(&se, &["userPrincipalName"]);

        if let Some(bin_vals) = se.bin_attrs.get("objectGUID")
            && let Some(raw_guid) = bin_vals.first()
            && let Some(guid_str) = format_ad_object_guid(raw_guid)
        {
            identity.external_user_id = Some(guid_str);
            identity.external_user_id_type = Some("ad_object_guid".to_string());
        }
        if identity.external_user_id.is_none() {
            let fallback = identity.login_name.clone().or_else(|| identity.upn.clone());
            if let Some(v) = fallback {
                identity.external_user_id = Some(v);
                identity.external_user_id_type = Some("login_name".to_string());
            }
        }
    }

    Ok(LdapUserData {
        roles: roles.into_iter().collect(),
        profile,
        identity,
    })
}

/// Fetch AD/LDAP direct roles (memberOf DNs) for `login`.
///
/// This call uses service bind (`bind_dn` + `bind_password`) and does not
/// require user password.
pub async fn fetch_ldap_roles(cfg: &LdapAuthConfig, login: &str) -> Result<Vec<String>> {
    Ok(fetch_ldap_user_data(cfg, login).await?.roles)
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
