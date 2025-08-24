use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Derivative, Validate)]
#[derivative(Debug)]
pub struct VerifyTokenRequest {
    #[derivative(Debug = "ignore")]
    #[validate(length(min = 1))]
    token: String,
}

impl VerifyTokenRequest {
    pub fn new(token: String) -> Self {
        Self { token }
    }
    
    pub fn get_token(&self) -> &str {
        &self.token
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct VerifyTokenResponse {
    valid: bool,
}

impl VerifyTokenResponse {
    pub fn new(valid: bool) -> Self {
        Self { valid }
    }
    
    pub fn valid(&self) -> bool {
        self.valid
    }
}