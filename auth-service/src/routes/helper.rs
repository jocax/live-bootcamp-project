use std::collections::HashMap;
use std::future::Future;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use axum::response::IntoResponse;
use serde::de::DeserializeOwned;
use validator::{ValidationErrors};
use crate::api::error::{AuthAPIError, ValidationErrorResponse};
use crate::domain::data_stores::Standard2FaError;
use crate::services::hashmap_user_store::UserStoreError;

pub fn map_to_response<T>(status_code: StatusCode, headers: Option<HeaderMap>, data: T) -> impl IntoResponse
where
    T: serde::Serialize,
{
        (status_code, headers, Json(data))
}

pub fn map_user_store_error_to_response(error: UserStoreError) -> AuthAPIError {
    let auth_api_error = match error {
        UserStoreError::UserAlreadyExists => AuthAPIError::UserAlreadyExists,
        UserStoreError::UserNotFound => AuthAPIError::UserNotFound,
        UserStoreError::InvalidCredentials => AuthAPIError::InvalidCredentials,
        UserStoreError::UnexpectedError => AuthAPIError::UnexpectedError,
    };
    auth_api_error
}

pub fn map_standard_2fa_error_to_response(error: Standard2FaError) -> AuthAPIError {
    let standard_2fa_error = match error {
        _ => AuthAPIError::InvalidCredentials,
    };
    standard_2fa_error
}

// Improved validation error mapping function
pub fn map_validation_errors_to_response(errors: ValidationErrors) -> AuthAPIError {
    let mut error_map: HashMap<String, Vec<String>> = HashMap::new();

    for (field_name, field_errors) in errors.field_errors() {
        let messages: Vec<String> = field_errors
            .iter()
            .map(|error| {
                error.message
                    .as_ref()
                    .map(|msg| msg.to_string())
                    .unwrap_or_else(|| {
                        // Generate a default message based on the error code
                        match error.code.as_ref() {
                            "email" => "Invalid email format".to_string(),
                            "length" => "Invalid length".to_string(),
                            _ => format!("Invalid {}", field_name),
                        }
                    })
            })
            .collect();

        error_map.insert(field_name.to_string(), messages);
    }

    AuthAPIError::ValidationError(ValidationErrorResponse::new(error_map))
}

pub struct ValidatedJson<T>(pub T);

impl<S, T> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AuthAPIError;

    fn from_request(req: Request, state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            match Json::<T>::from_request(req, state).await {
                Ok(Json(value)) => Ok(ValidatedJson(value)),
                Err(_rejection) => {
                    let error_message = "Invalid JSON format".to_string();
                    let error_details = vec![error_message];
                    let mut errors = std::collections::HashMap::new();
                    errors.insert("json".to_string(), error_details);

                    Err(AuthAPIError::ValidationError(ValidationErrorResponse::new(errors)))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::header::SET_COOKIE;
    use serde_json;
    use crate::api::signup::SignUpResponse;
    use crate::api::verify_token::VerifyTokenResponse;
    use super::*;

    #[tokio::test]
    async fn test_build_success_response_without_headers() {

        let response_payload = SignUpResponse::new("User created successfully".to_string());
        let response = map_to_response(StatusCode::OK, None, response_payload).into_response();
        assert!(response.status().is_success());

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_value["message"], "User created successfully");

    }

    #[tokio::test]
    async fn test_build_success_response_with_headers() {

        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, "jwt=myToken; Path=/; HttpOnly; SameSite=Lax".parse().unwrap());

        let response_payload = VerifyTokenResponse::new(true);
        let response = map_to_response(StatusCode::OK, Some(headers), response_payload).into_response();
        assert!(response.status().is_success());

        let cookie_header = response.headers().get(SET_COOKIE).unwrap();
        assert_eq!(cookie_header.to_str().unwrap(), "jwt=myToken; Path=/; HttpOnly; SameSite=Lax");

    }

    #[tokio::test]
    async fn test_conflict_error_response() {

        let response = map_user_store_error_to_response(UserStoreError::UserAlreadyExists).into_response();
        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::CONFLICT);

    }

    #[tokio::test]
    async fn test_server_error_response() {

        let response = map_user_store_error_to_response(UserStoreError::UnexpectedError).into_response();
        assert!(response.status().is_server_error());
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    }

    #[tokio::test]
    async fn test_authentication_error_response() {

        let response = map_user_store_error_to_response(UserStoreError::InvalidCredentials).into_response();
        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    }

    #[tokio::test]
    async fn test_not_found_error_response() {

        let response = map_user_store_error_to_response(UserStoreError::UserNotFound).into_response();
        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

    }

}
