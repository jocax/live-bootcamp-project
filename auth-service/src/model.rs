use axum::Json;
use axum::response::{IntoResponse, Response};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct ErrorResponse {
    pub message: String,
}
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct SignUpRequest {
    email: String,
    #[derivative(Debug = "ignore")]
    password: String,
    requires2fa: bool,
}
impl SignUpRequest {

    pub fn new(email: String, password: String, requires2fa: bool) -> Self {
        Self {
            email,
            password,
            requires2fa,
        }
    }
    pub fn get_email(&self) -> String {
        self.email.clone()
    }
    pub fn get_password(&self) -> String {
        String::from("*****")
    }
    pub fn get_requires2fa(&self) -> bool {
        self.requires2fa
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct SignUpResponse {
    pub message: String,
}
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LoginRequest {
    pub email: String,
    #[derivative(Debug = "ignore")]
    pub password: String,
}

impl LoginRequest {
    pub fn new(email: String, password: String) -> Self {
        Self {
            email,
            password,
        }
    }
    pub fn get_email(&self) -> String {
        self.email.clone()
    }
    pub fn get_password(&self) -> String {
        String::from("*****")
    }
}
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LoginResponse {
}
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct Verify2FARequest {
    pub code: String,
}

impl Verify2FARequest {
    pub fn new(code: String) -> Self {
        Self {
            code,
        }
    }
    pub fn get_code(&self) -> String {
        self.code.clone()
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct Verify2FAResponse {}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct VerifyTokenRequest {
    pub token: String,
}
impl VerifyTokenRequest {

    pub fn new(token: String) -> Self {
        Self {
            token,
        }
    }
    pub fn get_token(&self) -> String {
        self.token.clone()
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct VerifyTokenResponse {}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LogoutRequest {
    pub token: String,
}

impl LogoutRequest {

    pub fn new(token: String) -> Self {
        Self {
            token,
        }
    }
    pub fn get_token(&self) -> String {
        self.token.clone()
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LogoutResponse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_up_request_and_ensure_debug_ignores_password() {
        let request = SignUpRequest::new("my@email.de".to_string(), "myPassword".to_string(), false);

        //with password
        let serialized = serde_json::to_string(&request).unwrap();
        assert_eq!(serialized, "{\"email\":\"my@email.de\",\"password\":\"myPassword\",\"requires2fa\":false}");

        //no password
        let request_debugged = format!("{:?}", request);
        assert_eq!(request_debugged, "SignUpRequest { email: \"my@email.de\", requires2fa: false }");
    }
}
