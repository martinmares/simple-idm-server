use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum PasswordError {
    #[error("Failed to hash password: {0}")]
    HashError(String),
    #[error("Failed to verify password: {0}")]
    VerifyError(String),
    #[error("Invalid password")]
    InvalidPassword,
}

pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| PasswordError::HashError(e.to_string()))
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, PasswordError> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|e| PasswordError::VerifyError(e.to_string()))?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_hash_from_argon2_0_5() {
        // Generated with Argon2 0.5.3; existing database hashes must remain valid.
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$bGVnYWN5LXRlc3Qtc2FsdA$rTW6z6fQMRjI0zMbL2W/oNUtRMtC0kCrdUI1l/++AHw";
        assert!(verify_password("legacy-test-password", hash).unwrap());
        assert!(!verify_password("wrong-password", hash).unwrap());
    }

    #[test]
    fn new_hashes_use_random_salts_and_reject_wrong_passwords() {
        let first = hash_password("test-password").unwrap();
        let second = hash_password("test-password").unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("test-password", &first).unwrap());
        assert!(!verify_password("wrong-password", &first).unwrap());
        assert!(verify_password("test-password", "invalid-hash").is_err());
    }
}
