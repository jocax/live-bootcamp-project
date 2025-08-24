use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Derivative, Validate)]
#[derivative(Debug)]
pub struct SignUpRequest {
    #[validate(email(message = "Valid email required"))]
    email: String,
    #[derivative(Debug = "ignore")]
    #[validate(length(min = 8, max = 32, message = "Password must be 8-32 characters"))]
    password: String,
    requires_2fa: bool,
}

impl SignUpRequest {
    pub fn new(email: String, password: String, requires2fa: bool) -> Self {
        Self {
            email,
            password,
            requires_2fa: requires2fa,
        }
    }
    pub fn get_email(&self) -> String {
        self.email.clone()
    }
    pub fn get_password(&self) -> String {
        String::from("*****")
    }
    pub fn get_requires2fa(&self) -> bool {
        self.requires_2fa
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct SignUpResponse {
    message: String,
}

impl SignUpResponse {
    pub fn new(message: String) -> Self {
        Self { message }
    }
    pub fn get_message(&self) -> String {
        self.message.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_up_request_and_ensure_debug_ignores_password() {
        let request = SignUpRequest::new("my@email.de".to_string(), "myPassword".to_string(), false);

        //with password
        let serialized = serde_json::to_string(&request).unwrap();
        assert_eq!(serialized, "{\"email\":\"my@email.de\",\"password\":\"myPassword\",\"requires_2fa\":false}");

        //no password
        let request_debugged = format!("{:?}", request);
        assert_eq!(request_debugged, "SignUpRequest { email: \"my@email.de\", requires_2fa: false }");
    }
}
