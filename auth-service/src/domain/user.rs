use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Derivative, Validate, Clone, PartialEq, Eq)]
#[derivative(Debug)]
pub struct User {
    #[validate(email(message = "Valid email required"))]
    email: String,
    // #[derivative(Debug = "ignore")]
    #[derivative(Debug(format_with = "debug_masked"))]
    #[validate(length(min = 8, max = 32, message = "Password must be 8-32 characters"))]
    password: String,
    requires_2fa: bool,
}

impl User {
    pub fn new(email: String, password: String, requires2fa: bool) -> Self {
        Self {
            email,
            password: encrypt_password(password.as_str()).unwrap(),
            requires_2fa: requires2fa,
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        match PasswordHash::new(&self.password) {
            Ok(parsed_hash) => {
                let argon2 = Argon2::default();
                argon2
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok()
            }
            Err(_) => false,
        }
    }

    //GETTER
    pub fn get_email(&self) -> String {
        self.email.clone()
    }
    pub fn get_password(&self) -> String {
        if self.password.is_empty() {
            return String::from("");
        }
        String::from("*****")
    }
    pub fn get_requires2fa(&self) -> bool {
        self.requires_2fa
    }

    // SETTER
    pub fn set_email(&mut self, email: String) {
        self.email = email;
    }
    pub fn set_password(&mut self, password: String) {
        self.password = password;
    }
    pub fn set_requires2fa(&mut self, requires2fa: bool) {
        self.requires_2fa = requires2fa;
    }
}

// Helper function to mask the password
fn debug_masked(
    value: &String,
    formatter: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    if value.is_empty() {
        return write!(formatter, "");
    }
    write!(formatter, "\"*****\"")
}

fn encrypt_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    Ok(password_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_request_and_ensure_debug_ignores_password() {
        let user = User::new("my@email.de".to_string(), "myPassword".to_string(), false);

        //with password
        let serialized = serde_json::to_string(&user).unwrap();
        // Check structure
        assert!(serialized.starts_with("{"));
        assert!(serialized.ends_with("}"));

        // Check contains expected fields
        assert!(serialized.contains("\"email\":\"my@email.de\""));
        assert!(serialized.contains("\"requires_2fa\":false"));
        assert!(serialized.contains("\"password\":\"$argon2id$"));

        // Check does NOT contain plain password
        assert!(!serialized.contains("\"password\":\"myPassword\""));

        // Parse and check password field specifically
        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        let password_value = parsed["password"].as_str().unwrap();

        assert!(password_value.starts_with("$argon2id$v=19$m="));
        assert!(password_value.len() > 50);

        //no password
        let request_debugged = format!("{:?}", user);
        assert_eq!(
            request_debugged,
            "User { email: \"my@email.de\", password: \"*****\", requires_2fa: false }"
        );
    }

    #[test]
    fn test_user_verify_password() {
        let user = User::new("my@email.de".to_string(), "myPassword".to_string(), false);
        assert!(!user.verify_password("myPassword123"));
        assert!(user.verify_password("myPassword"));
    }

    #[test]
    fn test_encrypt_password()  {
        let encrypted_password = encrypt_password("myPassword").unwrap();
        assert_ne!(encrypted_password, "myPassword");
        assert!(encrypted_password.starts_with("$argon2id"));
    }
}
