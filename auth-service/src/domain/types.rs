use argon2::Argon2;
use derivative::Derivative;
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationErrors};
use crate::validations::email::{validate_email_default};
use crate::validations::password::{validate_password_default};

#[derive(Serialize, Deserialize, Derivative, Validate, Clone, Eq, PartialEq, Hash)]
#[derivative(Debug)]
pub struct Email {
    #[validate(
        custom(function = "validate_email_default", message = "Email must have a valid domain with TLD")
    )]
    value: String
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.value.as_ref()
    }
}

impl TryFrom<String> for Email {
    type Error = ValidationErrors;

    fn try_from(email: String) -> Result<Self, Self::Error> {
        let email_struct = Email { value: email };
        email_struct.validate()?;
        Ok(email_struct)
    }
}

impl TryFrom<&str> for Email {
    type Error = ValidationErrors;

    fn try_from(email: &str) -> Result<Self, Self::Error> {
        let email_struct = Email { value: email.to_string() };
        email_struct.validate()?;
        Ok(email_struct)
    }
}

#[derive(Serialize, Deserialize, Derivative, Validate, Clone, PartialEq, Eq)]
pub struct Password {
    #[validate(
        custom(function = "validate_password_default", message = "Password not valid")
    )]
    value: String
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.value
    }
}
impl TryFrom<String> for Password {
    type Error = ValidationErrors;

    fn try_from(password: String) -> Result<Self, Self::Error> {
        let mut password_struct = Password { value: password };
        password_struct.validate()?;
        password_struct.encrypt_password().expect("Failed to encrypt password");
        Ok(password_struct)
    }
}

impl TryFrom<&str> for Password {
    type Error = ValidationErrors;

    fn try_from(password: &str) -> Result<Self, Self::Error> {
        let mut password_struct = Password { value: password.to_string() };
        password_struct.validate()?;
        password_struct.encrypt_password().expect("Failed to encrypt password");
        Ok(password_struct)
    }
}

impl Password {

    fn encrypt_password(&mut self) -> Result<(), password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(self.value.as_bytes(), &salt)?;
        self.value = password_hash.to_string();
        Ok(())
    }

    pub fn verify_password(&self, password: &str) -> bool {
        match PasswordHash::new(&self.value) {
            Ok(parsed_hash) => {
                let argon2 = Argon2::default();
                argon2
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok()
            }
            Err(_) => false,
        }
    }

}

// Manual Debug implementation
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Password")
            .field("value", &"*****")
            .finish()
    }
}

// Display implementation
impl std::fmt::Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "*****")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;
    use crate::domain::types;

    #[test]
    fn test_invalid_email_formats() {
        // Test various invalid email formats
        let invalid_emails = vec![
            "notanemail",           // missing @ and domain
            "@example.com",         // missing local part
            "user@",                // missing domain
            "user@domain",          // missing TLD (based on your custom validator)
            "user @example.com",    // space in local part
            "user@exam ple.com",    // space in domain
            "user@@example.com",    // double @
            "user@.com",            // missing domain name
            "user@domain.",         // trailing dot
            ".user@example.com",    // RFC 5321: local part cannot start with dot
            "user..name@example.com", // RFC 5321: local part cannot contain consecutive dots
            "user.@example.com",    // RFC 5321: local part cannot end with dot
            "",                     // empty string
            "user@",                // incomplete
            "@",                    // just @
        ];

        for email_str in invalid_emails {
            let email = Email::try_from(email_str.to_string());
            assert!(email.is_err(), "Email '{}' should be invalid", email_str);
        }
    }

    #[test]
    fn test_invalid_password_formats() {
        // Test various invalid password formats
        let invalid_passwords = vec![
            "",
            "1234567",
            "123456a",
            "1234567@",

        ];

        for password_str in invalid_passwords {
            let password = types::Password::try_from(password_str.to_string());
            assert!(password.is_err(), "Password '{}' should be invalid", password_str);
        }
    }

    #[test]
    fn test_encrypt_password()  {
        let password_str = "myPassword123";
        let encrypted_password = Password::try_from(password_str).unwrap();

        // The encrypted password should start with $argon2
        assert!(encrypted_password.value.starts_with("$argon2"));

        // Verify that the original password can be verified against the hash
        assert!(encrypted_password.verify_password(password_str));

        // Verify that a wrong password fails
        assert!(!encrypted_password.verify_password("wrongPassword123"));
    }

    #[test]
    fn test_asref_returns_hashed_password() {
        // Create a password
        let password = Password::try_from("MySecurePassword123!").unwrap();

        // Get the reference to the inner value using AsRef
        let password_ref: &str = password.as_ref();

        // The value should be a hashed password (Argon2 format)
        assert!(password_ref.starts_with("$argon2"));
        assert!(password_ref.len() > 50); // Argon2 hashes are quite long

        // It should NOT be the original password
        assert_ne!(password_ref, "MySecurePassword123!");
    }

    #[test]
    fn test_asref_can_be_used_in_generic_context() {
        fn takes_asref<T: AsRef<str>>(value: &T) -> usize {
            value.as_ref().len()
        }

        let password = Password::try_from("TestPassword456!").unwrap();
        let length = takes_asref(&password);

        // Should return the length of the hashed password
        assert!(length > 50);
    }

    #[test]
    fn test_asref_consistency() {
        let password = Password::try_from("ConsistentPassword789!").unwrap();

        // Multiple calls to as_ref should return the same reference
        let ref1: &str = password.as_ref();
        let ref2: &str = password.as_ref();

        assert_eq!(ref1, ref2);
        assert_eq!(ref1.as_ptr(), ref2.as_ptr()); // Same memory location
    }
}
