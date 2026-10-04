use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use simple_idm_core::ssh_signer::jwt_validator::TokenClaims;
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub bastion_id: String,
    pub tenant_id: String,
    pub issuer: String,
    pub expected_audience: String,
    pub signer_url: String,
    #[serde(default = "default_key_env")]
    pub bastion_key_env: String,
    pub known_hosts: PathBuf,
    pub audit_db: PathBuf,
    pub session_dir: PathBuf,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default = "default_sessions")]
    pub max_sessions: usize,
    #[serde(default)]
    pub trusted_proxies: Vec<std::net::IpAddr>,
    pub hosts: Vec<Host>,
}
fn default_key_env() -> String {
    "BASTION_SERVICE_KEY".into()
}
fn default_ttl() -> u64 {
    3600
}
fn default_retention() -> u32 {
    90
}
fn default_sessions() -> usize {
    64
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub environment: String,
    #[serde(default)]
    pub description: String,
    pub allowed_groups: Vec<String>,
    pub logins: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<String>>,
}
fn default_port() -> u16 {
    22
}
#[derive(Debug, Serialize)]
pub struct VisibleHost {
    pub address: String,
    pub port: u16,
    pub resolved_ips: Vec<String>,
    pub id: String,
    pub name: String,
    pub environment: String,
    pub description: String,
    pub logins: Vec<String>,
}
pub fn linux_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}
pub fn dimensions(cols: u16, rows: u16) -> Result<()> {
    ensure!(
        (1..=1000).contains(&cols) && (1..=1000).contains(&rows),
        "terminal dimensions must be 1..1000"
    );
    Ok(())
}
pub fn terminal(term: &str) -> Result<()> {
    ensure!(
        !term.is_empty()
            && term.len() <= 64
            && term
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-+.".contains(&b)),
        "invalid terminal type"
    );
    Ok(())
}
fn service_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url)?;
    ensure!(
        parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "service URL must not contain credentials/query/fragment"
    );
    let loopback = parsed.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    ensure!(
        parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback),
        "service URLs require HTTPS except loopback"
    );
    Ok(())
}
impl Config {
    pub fn read(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.bind.ip().is_loopback(),
            "V1 binds only loopback HTTP behind TLS nginx"
        );
        ensure!(
            !self.tenant_id.trim().is_empty() && !self.expected_audience.trim().is_empty(),
            "tenant_id and expected_audience are required"
        );
        ensure!(
            identifier(&self.bastion_id) && identifier(&self.bastion_key_env),
            "invalid bastion ID/key environment name"
        );
        service_url(&self.issuer)?;
        service_url(&self.signer_url)?;
        ensure!(
            (1..=86400).contains(&self.ttl_seconds)
                && self.retention_days > 0
                && (1..=4096).contains(&self.max_sessions),
            "invalid TTL/retention/session limit"
        );
        for path in [&self.known_hosts, &self.audit_db, &self.session_dir] {
            ensure!(
                path.is_absolute() && !path.to_string_lossy().contains(['\n', '\r', '%', '\0']),
                "paths must be absolute and contain no OpenSSH expansion/control characters"
            );
        }
        let mut ids = HashSet::new();
        for host in &self.hosts {
            ensure!(
                identifier(&host.id) && ids.insert(&host.id),
                "invalid/duplicate host ID"
            );
            ensure!(
                !host.name.trim().is_empty() && host.port > 0,
                "invalid host name/port"
            );
            ensure!(
                !host.address.is_empty()
                    && !host.address.starts_with('-')
                    && host.address.len() <= 253
                    && host
                        .address
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b)),
                "invalid host address"
            );
            ensure!(
                !host.allowed_groups.is_empty()
                    && host.allowed_groups.iter().all(|g| !g.trim().is_empty()),
                "host requires groups"
            );
            ensure!(
                !host.logins.is_empty()
                    && host
                        .logins
                        .iter()
                        .all(|l| l == "{username}" || linux_user(l)),
                "invalid host logins"
            );
            if let Some(principals) = &host.principals {
                ensure!(
                    !principals.is_empty()
                        && principals.iter().all(|p| !p.is_empty()
                            && p.len() <= 128
                            && p.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))),
                    "invalid host principals"
                );
            }
        }
        Ok(())
    }
    pub fn authorize_identity(&self, claims: &TokenClaims) -> Result<()> {
        ensure!(
            claims.tenant_id.as_deref() == Some(self.tenant_id.as_str()),
            "tenant denied"
        );
        ensure!(
            claims.nonce.is_none(),
            "ID tokens are not API access tokens"
        );
        ensure!(
            claims
                .scope
                .as_deref()
                .is_some_and(|s| s.split_whitespace().any(|s| s == "bastion:connect")),
            "bastion:connect scope required"
        );
        ensure!(!claims.sub.is_empty(), "subject required");
        Ok(())
    }
    pub fn logins(&self, host: &Host, claims: &TokenClaims) -> Vec<String> {
        if self.authorize_identity(claims).is_err()
            || !host
                .allowed_groups
                .iter()
                .any(|g| claims.groups.contains(g))
        {
            return vec![];
        }
        let mut logins = Vec::new();
        for template in &host.logins {
            let login = if template == "{username}" {
                claims.preferred_username.as_deref().unwrap_or("")
            } else {
                template
            };
            if linux_user(login) && !logins.iter().any(|l| l == login) {
                logins.push(login.to_string());
            }
        }
        logins
    }
    pub fn select(&self, id: &str, login: &str, claims: &TokenClaims) -> Result<Host> {
        let host = self.hosts.iter().find(|h| h.id == id);
        if let Some(host) = host
            && self.logins(host, claims).iter().any(|l| l == login)
        {
            return Ok(host.clone());
        }
        bail!("host or login denied")
    }
    pub fn catalog(&self, claims: &TokenClaims) -> Vec<VisibleHost> {
        self.hosts
            .iter()
            .filter_map(|host| {
                let logins = self.logins(host, claims);
                (!logins.is_empty()).then(|| VisibleHost {
                    address: host.address.clone(),
                    port: host.port,
                    resolved_ips: Vec::new(),
                    id: host.id.clone(),
                    name: host.name.clone(),
                    environment: host.environment.clone(),
                    description: host.description.clone(),
                    logins,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        toml::from_str(include_str!("../examples/bastion.toml")).unwrap()
    }
    fn claims() -> TokenClaims {
        serde_json::from_value(serde_json::json!({"sub":"user-1","iss":"https://idm.example.com","aud":["ssh-login"],"exp":2000000000,"preferred_username":"alice","groups":["infra-admins"],"tenant_id":"tenant-1","scope":"openid bastion:connect"})).unwrap()
    }
    #[test]
    fn catalog_enforces_identity_groups_and_mapping() {
        let c = config();
        c.validate().unwrap();
        let mut t = claims();
        assert_eq!(c.catalog(&t)[0].logins, vec!["alice", "postgres"]);
        assert_eq!(c.catalog(&t)[0].address, c.hosts[0].address);
        assert_eq!(c.catalog(&t)[0].port, c.hosts[0].port);
        assert!(c.select("grafana", "root", &t).is_err());
        t.preferred_username = Some("-oProxyCommand=evil".into());
        assert_eq!(c.catalog(&t)[0].logins, vec!["postgres"]);
        t.groups.clear();
        assert!(c.catalog(&t).is_empty());
        t = claims();
        t.tenant_id = Some("other".into());
        assert!(c.catalog(&t).is_empty());
        t = claims();
        t.scope = Some("bastion:connect-extra".into());
        assert!(c.authorize_identity(&t).is_err());
        t = claims();
        t.nonce = Some("nonce".into());
        assert!(c.authorize_identity(&t).is_err());
        t = claims();
        t.tenant_id = None;
        assert!(c.authorize_identity(&t).is_err());
    }
    #[test]
    fn rejects_config_and_terminal_injection() {
        let mut colon = config();
        colon.hosts[0].principals = Some(vec!["role:ops".into()]);
        colon.validate().unwrap();
        let mut c = config();
        c.bind = "0.0.0.0:8080".parse().unwrap();
        assert!(c.validate().is_err());
        let mut c = config();
        c.hosts[0].address = "-oProxyCommand=evil".into();
        assert!(c.validate().is_err());
        let mut c = config();
        c.hosts.push(c.hosts[0].clone());
        assert!(c.validate().is_err());
        for term in ["", "xterm\nfoo", "xterm;touch /tmp/a", "$(id)"] {
            assert!(terminal(term).is_err());
        }
        terminal("xterm-256color").unwrap();
        assert!(dimensions(0, 24).is_err());
    }
}
