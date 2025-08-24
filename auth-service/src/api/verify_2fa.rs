use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Derivative, Validate)]
#[derivative(Debug)]
pub struct Verify2FARequest {
    #[validate(length(min = 6, max = 6, message = "Token must be 6 characters"))]
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
