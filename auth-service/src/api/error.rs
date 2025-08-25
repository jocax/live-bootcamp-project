use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationErrorResponse {
    errors: HashMap<String, Vec<String>>,
}

impl ValidationErrorResponse {
    pub fn new(errors: HashMap<String, Vec<String>>) -> Self {
        Self { errors }
    }

    pub fn get_errors(&self) -> &HashMap<String, Vec<String>> {
        &self.errors
    }
}

pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    InvalidFormat,
    ValidationError(ValidationErrorResponse),
    UserNotFound,
    UnexpectedError,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        match self {
            AuthAPIError::UserAlreadyExists => {
                let body = Json(ErrorResponse {
                    error: "User already exists".to_string(),
                });
                (StatusCode::CONFLICT, body).into_response()
            }
            AuthAPIError::InvalidCredentials => {
                let body = Json(ErrorResponse {
                    error: "Invalid credentials".to_string(),
                });
                (StatusCode::BAD_REQUEST, body).into_response()
            }
            AuthAPIError::InvalidFormat => {
                let body = Json(ErrorResponse {
                    error: "Invalid format".to_string(),
                });
                (StatusCode::BAD_REQUEST, body).into_response()
            }
            AuthAPIError::ValidationError(validation_response) => {
                (StatusCode::BAD_REQUEST, Json(validation_response)).into_response()
            }
            AuthAPIError::UserNotFound => {
                let body = Json(ErrorResponse {
                    error: "User not found".to_string(),
                });
                (StatusCode::NOT_FOUND, body).into_response()
            }
            AuthAPIError::UnexpectedError => {
                let body = Json(ErrorResponse {
                    error: "Unexpected error".to_string(),
                });
                (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
            }
        }
    }
}
