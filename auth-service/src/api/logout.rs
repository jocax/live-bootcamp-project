use derivative::Derivative;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LogoutRequest {
    token: String,
}

impl LogoutRequest {
    pub fn new(token: String) -> Self {
        Self { token }
    }
    pub fn get_token(&self) -> String {
        self.token.clone()
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LogoutResponse {}

impl LogoutResponse {
    pub fn new() -> Self {
        Self {}
    }
}
