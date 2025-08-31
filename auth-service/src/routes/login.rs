use crate::api::error::AuthAPIError;
use crate::api::login::{LoginRequest, LoginResponse};
use crate::routes::helper;
use crate::routes::helper::{map_validation_errors_to_response, ValidatedJson};
use crate::AppState;
use axum::extract::State;
use axum::http::header::{CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use validator::Validate;

pub async fn login_handler(
    State(app_state): State<AppState>,
    ValidatedJson(request): ValidatedJson<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the request
    let validation_result = request.validate();

    if validation_result.is_err() {
        return Err(map_validation_errors_to_response(
            validation_result.unwrap_err().to_owned(),
        ));
    }

    let email = request.get_email();
    let password = request.get_password();

    let user_state = &app_state.user_store;

    let password_validation_result = user_state
        .read()
        .await
        .validate_user(email, password.as_ref());

    if password_validation_result.is_err() {
        let error = password_validation_result.unwrap_err();
        Err(helper::map_user_store_error_to_response(error))
    } else {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(
            SET_COOKIE,
            "jwt=myToken; Path=/; HttpOnly; SameSite=Lax"
                .parse()
                .unwrap(),
        );

        Ok((StatusCode::OK, headers, Json(LoginResponse::new())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::login::LoginRequest;
    use crate::domain::data_stores::MockUserStore;
    use axum::body::to_bytes;
    use axum::response::Response;
    use serde_json::{json, Value};

    // Helper function to create app state with mock user store
    fn create_app_state_with_mock<F>(setup: F) -> AppState
    where
        F: FnOnce(&mut MockUserStore),
    {
        let mut mock_user_store = MockUserStore::new();
        setup(&mut mock_user_store);

        AppState {
            user_store: std::sync::Arc::new(tokio::sync::RwLock::new(mock_user_store)),
        }
    }

    // Helper function to create a login request
    fn create_login_request(email: &str, password: &str) -> LoginRequest {
        LoginRequest::new(
            crate::domain::types::Email::try_from(email).unwrap(),
            password.to_owned(),
        )
    }

    // Helper function to extract JSON body from response
    async fn extract_json_body(response: Response) -> Value {
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    #[tokio::test]
    async fn test_login_handler() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock| {
            mock.expect_validate_user().returning(|_, _| Ok(()));
        });

        let login_request = create_login_request("user@example.com", "password123");
        let request = ValidatedJson(login_request); // Changed from Json to ValidatedJson

        let response = login_handler(State(app_state), request)
            .await
            .unwrap()
            .into_response();
        assert!(response.status().is_success());

        let response_headers = response.headers();
        assert!(response_headers.contains_key(SET_COOKIE));
        assert_eq!(
            response_headers.get(SET_COOKIE).unwrap(),
            "jwt=myToken; Path=/; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            response_headers.get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let expected_body = extract_json_body(response).await;
        assert_eq!(expected_body, json!({}))
    }
}
