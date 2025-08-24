use axum::http::{StatusCode};
use axum::Json;
use axum::response::{IntoResponse, Response};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct ErrorResponse {
    error: String,
}

impl ErrorResponse {
    pub fn new(error: String) -> Self {
        Self { error }
    }

    pub fn get_error(&self) -> &String {
        &self.error
    }
}

pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    InvalidFormat,
    UserNotFound,
    UnexpectedError,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::InvalidFormat => (StatusCode::BAD_REQUEST, "Invalid format"),
            AuthAPIError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}


