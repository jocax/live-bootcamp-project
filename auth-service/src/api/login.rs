use crate::domain::types::Email;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Derivative, Validate)]
#[derivative(Debug)]
pub struct LoginRequest {
    email: Email,
    #[derivative(Debug = "ignore")]
    password: String,
}

impl LoginRequest {
    pub fn new(email: Email, password: String) -> Self {
        Self { email, password }
    }

    pub fn get_email(&self) -> &Email {
        &self.email
    }

    pub fn get_password(&self) -> &String {
        &self.password
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth(LoginRegularAuthResponse),
    TwoFactorAuth(Login2FaRequiredResponse),
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct RegularAuth {}

impl RegularAuth {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
#[derive(PartialEq)]
pub struct Login2FaRequiredResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

impl Login2FaRequiredResponse {
    pub fn new(message: String, login_attempt_id: String) -> Self {
        Self {
            message,
            login_attempt_id,
        }
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
#[derive(PartialEq)]
pub struct LoginRegularAuthResponse {
    success: bool,
    redirect_url: String,
}

impl LoginRegularAuthResponse {
    pub fn new(success: bool, redirect_url: String) -> Self {
        Self {
            success,
            redirect_url,
        }
    }
}
