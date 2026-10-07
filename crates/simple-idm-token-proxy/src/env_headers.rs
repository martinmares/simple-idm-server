use std::{collections::HashSet, str::FromStr};

use anyhow::Context;
use axum::http::{HeaderMap, HeaderName, HeaderValue};

#[derive(Debug, Clone)]
pub struct EnvHeader {
    pub env: String,
    pub header: HeaderName,
}

impl FromStr for EnvHeader {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (env, header) = value
            .split_once('=')
            .ok_or("expected ENV_NAME=X-Header-Name")?;
        let mut characters = env.chars();
        if !characters
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err("environment name must match [A-Za-z_][A-Za-z0-9_]*".into());
        }
        let header = HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| "invalid HTTP header name".to_string())?;
        if !header.as_str().starts_with("x-") || header.as_str().len() == 2 {
            return Err("mapped header must be an X-* header".into());
        }
        Ok(Self {
            env: env.to_string(),
            header,
        })
    }
}

#[derive(Clone, Default)]
pub struct ManagedHeaders {
    pub names: HashSet<HeaderName>,
    pub values: HeaderMap,
}

impl ManagedHeaders {
    pub fn insert(&mut self, name: HeaderName, value: Option<HeaderValue>) {
        self.names.insert(name.clone());
        if let Some(mut value) = value {
            value.set_sensitive(true);
            self.values.insert(name, value);
        }
    }

    pub fn resolve(
        mappings: &[EnvHeader],
        read_env: &mut impl FnMut(&str) -> anyhow::Result<Option<String>>,
    ) -> anyhow::Result<Self> {
        let mut headers = Self::default();
        for mapping in mappings {
            if headers.names.contains(&mapping.header) {
                anyhow::bail!("duplicate --env-header destination: {}", mapping.header);
            }
            let value = read_env(&mapping.env)?
                .filter(|value| !value.is_empty())
                .map(|value| {
                    HeaderValue::from_str(&value).with_context(|| {
                        format!(
                            "invalid HTTP header value in environment variable {}",
                            mapping.env
                        )
                    })
                })
                .transpose()?;
            headers.insert(mapping.header.clone(), value);
        }
        Ok(headers)
    }
}

pub fn read_process_env(name: &str) -> anyhow::Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("environment variable {name} is not valid UTF-8")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_mapping_names() {
        let mapping: EnvHeader = "APP_TENANT=X-Tenant".parse().unwrap();
        assert_eq!(mapping.env, "APP_TENANT");
        assert_eq!(mapping.header, "x-tenant");
        for invalid in [
            "APP_TENANT",
            "=X-Tenant",
            "1APP=X-Tenant",
            "APP NAME=X-Tenant",
            "APP=X-",
            "APP=Authorization",
            "APP=Host",
            "APP=X Bad",
            "APP=X-Tenant\nInjected",
        ] {
            assert!(
                invalid.parse::<EnvHeader>().is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn resolves_optional_values_and_rejects_duplicates_and_injection() {
        let mappings = [
            "TENANT=X-Tenant",
            "MISSING=X-Optional",
            "EMPTY=X-Empty",
            "TENANT=X-Other",
        ]
        .map(|value| value.parse().unwrap());
        let headers = ManagedHeaders::resolve(&mappings, &mut |name| {
            Ok(match name {
                "TENANT" => Some("default / tenant".into()),
                "EMPTY" => Some(String::new()),
                _ => None,
            })
        })
        .unwrap();
        assert_eq!(headers.values["x-tenant"], "default / tenant");
        assert_eq!(headers.values["x-other"], "default / tenant");
        assert!(headers.values["x-tenant"].is_sensitive());
        assert!(
            headers
                .names
                .contains(&HeaderName::from_static("x-optional"))
        );
        assert!(!headers.values.contains_key("x-optional"));
        assert!(!headers.values.contains_key("x-empty"));
        let duplicate = ["ONE=X-Tenant", "TWO=x-tenant"].map(|value| value.parse().unwrap());
        assert!(ManagedHeaders::resolve(&duplicate, &mut |_| Ok(None)).is_err());
        let error = ManagedHeaders::resolve(&mappings[..1], &mut |_| {
            Ok(Some("secret\r\nInjected: yes".into()))
        })
        .err()
        .unwrap();
        assert!(error.to_string().contains("TENANT"));
        assert!(!format!("{error:#}").contains("secret"));
    }
}
