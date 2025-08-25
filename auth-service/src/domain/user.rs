use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::domain::types::{Email, Password};

#[derive(Serialize, Deserialize, Derivative, Validate, Clone, PartialEq, Eq)]
#[derivative(Debug)]
pub struct User {
    email: Email,
    password: Password,
    requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires2fa: bool) -> Self {
        Self {
            email,
            password,
            requires_2fa: requires2fa,
        }
    }

    //GETTER
    pub fn get_email(&self) -> Email {
        self.email.clone()
    }
    pub fn get_password(&self) -> Password {
        self.password.clone()
    }

    pub fn get_requires2fa(&self) -> bool {
        self.requires_2fa
    }

    // SETTER
    pub fn set_email(&mut self, email: Email) {
        self.email = email;
    }
    pub fn set_password(&mut self, password: Password) {
        self.password = password;
    }
    pub fn set_requires2fa(&mut self, requires2fa: bool) {
        self.requires_2fa = requires2fa;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_request_and_ensure_debug_ignores_password() {
        let email = Email::try_from("my@email.de".to_string()).unwrap();
        let password = Password::try_from("myPassword123".to_string()).unwrap();
        let user = User::new(email, password, false);

        //with password
        let serialized = serde_json::to_string(&user).unwrap();
        // Check structure
        assert!(serialized.starts_with("{"));
        assert!(serialized.ends_with("}"));

        // Check contains expected fields
        assert!(serialized.contains("\"value\":\"my@email.de\""));
        assert!(serialized.contains("\"requires_2fa\":false"));
        assert!(serialized.contains("\"value\":\"$argon2id$"));

        // Check does NOT contain plain password
        assert!(!serialized.contains("\"value\":\"myPassword\""));

        //no password
        let request_debugged = format!("{:?}", user);
        assert_eq!(
            request_debugged,
            "User { email: Email { value: \"my@email.de\" }, password: Password { value: \"*****\" }, requires_2fa: false }"
        );
    }

    #[test]
    fn test_user_verify_password() {
        let password_value = "myPassword123";
        let email = Email::try_from("my@email.de").unwrap();
        let password = Password::try_from(password_value.to_string()).unwrap();

        let user = User::new(email, password, false);

        assert!(user.get_password().verify_password(password_value));

        // let password_invalid = Password::try_from("myPassword".to_string()).unwrap();
        // assert!(!user.verify_password(&password_invalid))
    }

}
