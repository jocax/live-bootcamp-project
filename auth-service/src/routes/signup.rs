use crate::api::error::{AuthAPIError};
use crate::api::signup::{SignUpRequest, SignUpResponse};
use crate::domain::user::User;
use crate::routes::helper::{
    map_to_response, map_user_store_error_to_response, map_validation_errors_to_response,
};
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use validator::Validate;
use crate::domain::types::{Email, Password};

pub async fn signup_handler(
    State(app_state): State<AppState>,
    Json(request): Json<SignUpRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {

    // Validate the request
    let validation_result = request.validate();

    if validation_result.is_err() {
        return  Err(map_validation_errors_to_response(
            validation_result.unwrap_err().to_owned()));
    }

    let email = request.get_email();
    let password = request.get_password();

    let user = User::new(
        Email::try_from(email).unwrap(),
        Password::try_from(password).unwrap(),
        request.get_requires2fa(),
    );

    let mut user_store = app_state.user_store.write().await;

    let result = user_store.add_user(user).await;

    if result.is_ok() {
        Ok(map_to_response(
            StatusCode::CREATED,
            None,
            SignUpResponse::new("User created successfully!".to_string()),
        ))
    } else {
        Err(map_user_store_error_to_response(result.unwrap_err()))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::response::Response;
    use fake::rand::distr::Alphanumeric;
    use fake::rand::{rng};
    use fake::Rng;
    use serde_json::Value;
    use crate::domain::data_stores::{MockBannedTokenStore, MockStandard2FaStore, MockUserStore, UserStoreError};
    use crate::domain::email_client::MockEmailClient;
    use super::*;

    // Helper function to create app state with mock user store and banned token store
    fn create_app_state_with_mock<F>(setup: F) -> AppState
    where
        F: FnOnce(&mut MockUserStore, &mut MockBannedTokenStore, &mut MockStandard2FaStore, &mut MockEmailClient),
    {
        let mut mock_user_store = MockUserStore::new();
        let mut mock_banned_token_store = MockBannedTokenStore::new();
        let mut mock_standard_2fa_code_store = MockStandard2FaStore::new();
        let mut mock_email_client = MockEmailClient::new();

        setup(&mut mock_user_store, &mut mock_banned_token_store, &mut mock_standard_2fa_code_store, &mut mock_email_client);

        AppState {
            user_store: std::sync::Arc::new(tokio::sync::RwLock::new(mock_user_store)),
            banned_token_store: std::sync::Arc::new(tokio::sync::RwLock::new(mock_banned_token_store)),
            standard_2fa_code_store:  std::sync::Arc::new(tokio::sync::RwLock::new(mock_standard_2fa_code_store)),
            email_client:  std::sync::Arc::new(tokio::sync::RwLock::new(mock_email_client)),
        }
    }

    // Helper function to create a signup request
    fn create_signup_request(email: &str, password: &str, requires_2fa: bool) -> SignUpRequest {
        SignUpRequest::new(
            email.to_string(),
            password.to_string(),
            requires_2fa,
        )
    }

    // Helper function to extract JSON body from response
    async fn extract_json_body(response: Response) -> Value {
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    #[tokio::test]
    async fn test_signup_handler_success() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().returning(|_| Ok(()));
        });

        let signup_request = create_signup_request("user@example.com", "password123", false);
        let request = Json(signup_request);

        // Act
        let response = signup_handler(State(app_state), request).await.into_response();

        // Assert
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_signup_handler_invalid_email_format() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().never();
        });

        let signup_request = create_signup_request("invalid-email", "password123", false);
        let request = Json(signup_request);

        // Act
        let result = signup_handler(State(app_state), request).await;

        // Assert
        assert!(result.is_err());
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Verify error message
        let body = extract_json_body(response).await;
        assert!(body["errors"]["email"].is_array());
        assert_eq!(body["errors"]["email"][0], "Email must have a valid domain with TLD");
    }

    #[tokio::test]
    async fn test_signup_handler_empty_email() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().never();
        });

        let signup_request = create_signup_request("", "password123", false);
        let request = Json(signup_request);

        // Act
        let result = signup_handler(State(app_state), request).await;

        // Assert
        assert!(result.is_err());
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let body = extract_json_body(response).await;
        assert!(body["errors"]["email"].is_array());
        assert_eq!(body["errors"]["email"][0], "Email must have a valid domain with TLD");
    }

    #[tokio::test]
    async fn test_signup_handler_password_too_short() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().never();
        });

        let signup_request = create_signup_request("user@example.com", "short", false);
        let request = Json(signup_request);

        // Act
        let result = signup_handler(State(app_state), request).await;

        // Assert
        assert!(result.is_err());
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let body = extract_json_body(response).await;
        assert!(body["errors"]["password"].is_array());
        assert_eq!(body["errors"]["password"][0], "Password must be 8-32 characters, must contain at least letters and numbers");
    }

    #[tokio::test]
    async fn test_signup_handler_password_too_long() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().never();
        });

        let long_password = "a".repeat(33);
        let signup_request = create_signup_request("user@example.com", &long_password, false);
        let request = Json(signup_request);

        // Act
        let result = signup_handler(State(app_state), request).await;

        // Assert
        assert!(result.is_err());
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let body = extract_json_body(response).await;
        assert!(body["errors"]["password"].is_array());
        assert_eq!(body["errors"]["password"][0], "Password must be 8-32 characters, must contain at least letters and numbers");
    }

    #[tokio::test]
    async fn test_signup_handler_multiple_validation_errors() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().never();
        });

        // Both email and password invalid
        let signup_request = create_signup_request("not-an-email", "short", false);
        let request = Json(signup_request);

        // Act
        let result = signup_handler(State(app_state), request).await;

        // Assert
        assert!(result.is_err());
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let body = extract_json_body(response).await;
        // Should have errors for both fields
        assert!(body["errors"]["email"].is_array());
        assert!(body["errors"]["password"].is_array());
        assert_eq!(body["errors"]["email"][0], "Email must have a valid domain with TLD");
        assert_eq!(body["errors"]["password"][0], "Password must be 8-32 characters, must contain at least letters and numbers");
    }

    #[tokio::test]
    async fn test_signup_handler_password_exactly_8_chars() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().returning(|_| Ok(()));
        });

        let signup_request = create_signup_request("user@example.com", "1234567A", false);
        let request = Json(signup_request);

        // Act
        let response = signup_handler(State(app_state), request).await.into_response();

        // Assert
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_signup_handler_password_exactly_32_chars() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().returning(|_| Ok(()));
        });

        let password_32_chars: String = rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let signup_request = create_signup_request("user@example.com", &password_32_chars, false);
        let request = Json(signup_request);

        // Act
        let response = signup_handler(State(app_state), request).await.into_response();

        // Assert
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_signup_handler_valid_email_variations() {
        // Test various valid email formats
        let valid_emails = vec![
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.com",
            "user123@example.co.uk",
            "user_name@example-domain.com",
        ];

        for email in valid_emails {
            let app_state = create_app_state_with_mock(|mock, _, _,_| {
                mock.expect_add_user().returning(|_| Ok(()));
            });

            let signup_request = create_signup_request(email, "password123", false);
            let request = Json(signup_request);

            let response = signup_handler(State(app_state), request).await.into_response();
            assert_eq!(response.status(), StatusCode::CREATED, "Failed for email: {}", email);
        }
    }

    #[tokio::test]
    async fn test_signup_handler_invalid_email_variations() {
        // Test various invalid email formats
        let invalid_emails = vec![
            "notanemail",
            "@example.com",
            "user@",
            "user@@example.com",
            "user@example",
            "user @example.com",
            "user@exam ple.com",
        ];

        for email in invalid_emails {
            let app_state = create_app_state_with_mock(|mock, _, _,_| {
                mock.expect_add_user().never();
            });

            let signup_request = create_signup_request(email, "password123", false);
            let request = Json(signup_request);

            let result = signup_handler(State(app_state), request).await;
            assert!(result.is_err(), "Should have failed for email: {}", email);

            let response = result.into_response();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    #[tokio::test]
    async fn test_signup_handler_with_2fa_enabled() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user()
                .withf(|user| user.get_requires2fa() == true)
                .returning(|_| Ok(()));
        });

        let signup_request = create_signup_request("user@example.com", "password123", true);
        let request = Json(signup_request);

        // Act
        let response = signup_handler(State(app_state), request).await.into_response();

        // Assert
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_signup_handler_user_already_exists() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user()
                .returning(|_| Err(UserStoreError::UserAlreadyExists));
        });

        let signup_request = create_signup_request("existing@example.com", "password123", false);
        let request = Json(signup_request);

        // Act
        let result = signup_handler(State(app_state), request).await;

        // Assert
        assert!(result.is_err());
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    // Unit test for the map_validation_errors_to_response function
    #[test]
    fn test_map_validation_errors_to_response() {
        use validator::{ValidationError, ValidationErrors};

        // Create validation errors
        let mut errors = ValidationErrors::new();

        // Add email error
        let mut email_error = ValidationError::new("email");
        email_error.message = Some("Valid email required".into());
        errors.add("email", email_error);

        // Add password error
        let mut password_error = ValidationError::new("length");
        password_error.message = Some("Password must be 8-32 characters".into());
        errors.add("password", password_error);

        // Map errors
        let result = map_validation_errors_to_response(errors);

        // Verify result
        match result {
            AuthAPIError::ValidationError(response) => {
                assert_eq!(response.get_errors().len(), 2);
                assert_eq!(response.get_errors()["email"][0], "Valid email required");
                assert_eq!(response.get_errors()["password"][0], "Password must be 8-32 characters");
            }
            _ => panic!("Expected ValidationError variant"),
        }
    }

    #[tokio::test]
    async fn test_signup_handler_multiple_validation_errors_password_only_letters_email_invalid() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user().never();
        });

        // Both email and password invalid
        let signup_request = create_signup_request("user@email.x", "abcdefg", false);
        let request = Json(signup_request);

        // Act
        let result = signup_handler(State(app_state), request).await;

        // Assert
        assert!(result.is_err());
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let body = extract_json_body(response).await;
        // Should have errors for both fields
        assert!(body["errors"]["email"].is_array());
        assert!(body["errors"]["password"].is_array());
        assert_eq!(body["errors"]["email"][0], "Email must have a valid domain with TLD");
        assert_eq!(body["errors"]["password"][0], "Password must be 8-32 characters, must contain at least letters and numbers");
    }

    #[tokio::test]
    async fn test_signup_handler_unexpected_error_from_database_for_500_response() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock, _, _,_| {
            mock.expect_add_user()
                .returning(|_| Err(UserStoreError::UnexpectedError));
        });

        let signup_request = create_signup_request("user@example.com", "password123", false);
        let request = Json(signup_request);

        // Act
        let result = signup_handler(State(app_state), request).await;

        // Assert
        assert!(result.is_err());
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

}
