use derivative::Derivative;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct ErrorResponse {
    message: String,
}

impl ErrorResponse {
    pub fn new(message: String) -> Self {
        Self { message }
    }
    
    pub fn get_message(&self) -> &String {
        &self.message
    }
} 


