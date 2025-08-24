use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Derivative, Validate)]
#[derivative(Debug)]
pub struct LoginRequest {
    #[validate(email(message = "Valid email required"))]
    email: String,
    #[derivative(Debug = "ignore")]
    #[validate(length(min = 8, max = 32, message = "Password must be 8-32 characters"))]
    password: String,
}

impl LoginRequest {
    pub fn new(email: String, password: String) -> Self {
        Self { email, password } 
    }
    
    pub fn get_email(&self) -> &String {
        &self.email
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LoginResponse {}
