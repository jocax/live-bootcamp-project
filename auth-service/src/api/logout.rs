use derivative::Derivative;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct LogoutRequest {}

impl LogoutRequest {
    pub fn new() -> Self {
        Self {}
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
