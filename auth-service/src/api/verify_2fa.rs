use derivative::Derivative;
use serde::{Deserialize, Serialize};
use uuid::{Uuid};
use validator::{Validate, ValidationError};
use crate::domain::types::Email;

fn validate_uuid(id: &str) -> Result<(), ValidationError> {
    match Uuid::parse_str(id) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("login_attempt_id")),
    }
}

#[derive(Serialize, Deserialize, Derivative, Validate)]
#[derivative(Debug)]
pub struct Verify2FARequest {
    pub email: Email,

    #[serde(rename = "loginAttemptId")]
    #[validate(
        custom(function = "validate_uuid", message = "loginAttemptId must be a valid UUID")
    )]
    pub login_attempt_id: String,

    #[validate(length(min = 6, max = 6, message = "Token must be 6 characters"))]
    #[serde(rename = "2FACode")]
    pub code: String,
}


impl Verify2FARequest {
    pub fn new(email: Email, login_attempt_id: String, code: String) -> Self {
        Self {
            email, login_attempt_id,
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
