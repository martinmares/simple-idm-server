use crate::ssh_signer::jwt_validator::TokenClaims;
use regex::Regex;

pub struct PrincipalMapper {
    max_principals: usize,
    principal_max_len: usize,
    principal_regex: Regex,
}

impl PrincipalMapper {
    pub fn new(max_principals: usize, principal_max_len: usize) -> Self {
        // Allow only safe characters: alphanumeric, dot, underscore, colon, hyphen
        let principal_regex = Regex::new(r"^[A-Za-z0-9._:-]+$").unwrap();

        Self {
            max_principals,
            principal_max_len,
            principal_regex,
        }
    }

    pub fn map_principals(&self, claims: &TokenClaims) -> Result<Vec<String>, String> {
        let mut principals = Vec::new();

        // Parse groups and extract SSH principals
        for group in &claims.groups {
            if let Some(principal) = self.parse_ssh_principal(group) {
                principals.push(principal);
            }
        }

        // Fallback if no explicit ssh:principal:* found
        if principals.is_empty() {
            let fallback = self.get_fallback_principal(claims)?;
            principals.push(fallback);
        }

        // Validate all principals
        for principal in &principals {
            self.validate_principal(principal)?;
        }

        // Enforce max principals limit
        if principals.len() > self.max_principals {
            return Err(format!(
                "Too many principals: {} (max {})",
                principals.len(),
                self.max_principals
            ));
        }

        // Deduplicate
        principals.sort();
        principals.dedup();

        tracing::debug!(
            "Mapped principals for sub {}: {:?}",
            claims.sub,
            principals
        );

        Ok(principals)
    }

    fn parse_ssh_principal(&self, group: &str) -> Option<String> {
        // ssh:principal:<name> → <name>
        if let Some(stripped) = group.strip_prefix("ssh:principal:") {
            return Some(stripped.to_string());
        }

        // ssh:role:<role> → role:<role>
        if let Some(stripped) = group.strip_prefix("ssh:role:") {
            return Some(format!("role:{}", stripped));
        }

        None
    }

    fn get_fallback_principal(&self, claims: &TokenClaims) -> Result<String, String> {
        // Priority: preferred_username → email (without domain) → sub
        if let Some(username) = &claims.preferred_username {
            if !username.is_empty() {
                return Ok(username.clone());
            }
        }

        if let Some(email) = &claims.email {
            if !email.is_empty() {
                // Extract username part before @
                if let Some(username) = email.split('@').next() {
                    return Ok(username.to_string());
                }
            }
        }

        // Last resort: use sub
        Ok(claims.sub.clone())
    }

    fn validate_principal(&self, principal: &str) -> Result<(), String> {
        // Check length
        if principal.len() > self.principal_max_len {
            return Err(format!(
                "Principal '{}' too long: {} chars (max {})",
                principal,
                principal.len(),
                self.principal_max_len
            ));
        }

        // Check character whitelist
        if !self.principal_regex.is_match(principal) {
            return Err(format!(
                "Principal '{}' contains invalid characters (allowed: A-Za-z0-9._:-)",
                principal
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_principals_explicit() {
        let mapper = PrincipalMapper::new(32, 64);
        let claims = TokenClaims {
            sub: "user-123".to_string(),
            iss: "https://sso.example.com".to_string(),
            aud: vec!["ssh-login".to_string()],
            exp: 9999999999,
            preferred_username: Some("john".to_string()),
            email: Some("john@example.com".to_string()),
            groups: vec![
                "ssh:principal:john".to_string(),
                "ssh:role:devops".to_string(),
                "team:platform".to_string(), // ignored
            ],
        };

        let principals = mapper.map_principals(&claims).unwrap();
        assert_eq!(principals, vec!["john", "role:devops"]);
    }

    #[test]
    fn test_map_principals_fallback_preferred_username() {
        let mapper = PrincipalMapper::new(32, 64);
        let claims = TokenClaims {
            sub: "uuid-123-456".to_string(),
            iss: "https://sso.example.com".to_string(),
            aud: vec!["ssh-login".to_string()],
            exp: 9999999999,
            preferred_username: Some("alice".to_string()),
            email: Some("alice@example.com".to_string()),
            groups: vec!["team:engineering".to_string()], // no ssh:* groups
        };

        let principals = mapper.map_principals(&claims).unwrap();
        assert_eq!(principals, vec!["alice"]);
    }

    #[test]
    fn test_map_principals_fallback_email() {
        let mapper = PrincipalMapper::new(32, 64);
        let claims = TokenClaims {
            sub: "uuid-789".to_string(),
            iss: "https://sso.example.com".to_string(),
            aud: vec!["ssh-login".to_string()],
            exp: 9999999999,
            preferred_username: None,
            email: Some("bob@corp.com".to_string()),
            groups: vec![],
        };

        let principals = mapper.map_principals(&claims).unwrap();
        assert_eq!(principals, vec!["bob"]);
    }

    #[test]
    fn test_validate_principal_invalid_chars() {
        let mapper = PrincipalMapper::new(32, 64);
        assert!(mapper.validate_principal("user@host").is_err());
        assert!(mapper.validate_principal("user;rm -rf").is_err());
        assert!(mapper.validate_principal("user`whoami`").is_err());
    }

    #[test]
    fn test_validate_principal_too_long() {
        let mapper = PrincipalMapper::new(32, 10);
        assert!(mapper.validate_principal("verylongusername").is_err());
    }
}
