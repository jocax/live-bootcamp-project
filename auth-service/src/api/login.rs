use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::domain::types::{Email};

#[derive(Serialize, Deserialize, Derivative, Validate)]
#[derivative(Debug)]
pub struct LoginRequest {
    email: Email,
    #[derivative(Debug = "ignore")]
    password: String,
}

impl LoginRequest {
    pub fn new(email: Email, password: String) -> Self {
        Self { email,  password }
    }

    pub fn get_email(&self) -> &Email {
        &self.email
    }

    pub fn get_password(&self) -> &String {
        &self.password
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LoginResponse {}

impl LoginResponse {
    pub fn new() -> Self {
        Self {}
    }
}
