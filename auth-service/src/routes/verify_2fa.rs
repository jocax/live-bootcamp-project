use crate::api::error::AuthAPIError;
use crate::api::verify_2fa::{Verify2FARequest, Verify2FAResponse};
use crate::routes::helper::{
    map_standard_2fa_error_to_response, map_validation_errors_to_response, ValidatedJson,
};
use crate::{utils, AppState};
use axum::extract::State;
use axum::http::header::{CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;
use tracing::warn;
use validator::Validate;

pub async fn verify_2fa_handler(
    State(app_state): State<AppState>,
    cookie_jar: CookieJar,
    ValidatedJson(request): ValidatedJson<Verify2FARequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the request
    let validation_result = request.validate();

    if validation_result.is_err() {
        return Err(map_validation_errors_to_response(
            validation_result.unwrap_err().to_owned(),
        ));
    }

    let email = &request.email;
    let code = &request.code;

    let standard_2fa_info = app_state
        .standard_2fa_code_store
        .read()
        .await
        .has_active_2fa_code(email)
        .await;

    if standard_2fa_info.is_err() {
        return Err(map_standard_2fa_error_to_response(
            standard_2fa_info.unwrap_err(),
        ));
    }

    let standard_2fa_info_option = standard_2fa_info.unwrap();

    if standard_2fa_info_option.is_none() {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let standard_2fa_info = standard_2fa_info_option.unwrap();

    if standard_2fa_info.attempt_id != request.login_attempt_id {
        return Err(AuthAPIError::InvalidCredentials);
    }

    if standard_2fa_info.code_2fa != request.code {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let auth_cookie = match utils::auth::generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(error) => {
            warn!("Error generating auth cookie: {:?}", error);
            return Err(AuthAPIError::UnexpectedError);
        }
    };

    let rw_lock = app_state
        .standard_2fa_code_store
        .write()
        .await
        .verify_and_consume_2fa_code(email, code)
        .await;

    if rw_lock.is_err() {
        return Err(map_standard_2fa_error_to_response(
            rw_lock.unwrap_err(),
        ));
    }

    let updated_cookie_jar = cookie_jar.add(auth_cookie);

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

    Ok((
        StatusCode::OK,
        headers,
        updated_cookie_jar,
        Json::from(Verify2FAResponse::new   (
            true,
            "/app".to_string()
        )),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::data_stores::{MockBannedTokenStore, MockStandard2FaStore, MockUserStore, Standard2FaInfo};
    use crate::domain::email_client::MockEmailClient;
    use crate::domain::types::Email;
    use crate::routes::helper::ValidatedJson;
    use chrono::{Duration, Utc};
    use mockall::predicate::eq;
    use rstest::{fixture, rstest};
    use uuid::Uuid;

    // Helper function to create app state with mock user store and banned token store
    fn create_app_state_with_mock<F>(setup: F) -> AppState
    where
        F: FnOnce(
            &mut MockUserStore,
            &mut MockBannedTokenStore,
            &mut MockStandard2FaStore,
            &mut MockEmailClient,
        ),
    {
        let mut mock_user_store = MockUserStore::new();
        let mut mock_banned_token_store = MockBannedTokenStore::new();
        let mut mock_standard_2fa_code_store = MockStandard2FaStore::new();
        let mut mock_email_client = MockEmailClient::new();

        setup(
            &mut mock_user_store,
            &mut mock_banned_token_store,
            &mut mock_standard_2fa_code_store,
            &mut mock_email_client,
        );

        AppState {
            user_store: std::sync::Arc::new(tokio::sync::RwLock::new(mock_user_store)),
            banned_token_store: std::sync::Arc::new(tokio::sync::RwLock::new(
                mock_banned_token_store,
            )),
            standard_2fa_code_store: std::sync::Arc::new(tokio::sync::RwLock::new(
                mock_standard_2fa_code_store,
            )),
            email_client: std::sync::Arc::new(tokio::sync::RwLock::new(mock_email_client)),
        }
    }

    fn create_verify_2fa_request(email: &str, attempt_id: &str, code: &str) -> Verify2FARequest {
        Verify2FARequest::new(
            crate::domain::types::Email::try_from(email).unwrap(),
            attempt_id.to_string(),
            code.to_string(),
        )
    }

    #[fixture]
    fn verify_2fa_requests() -> Vec<Verify2FARequest> {
        vec![
            create_verify_2fa_request("user@example.com", "", ""),
            create_verify_2fa_request(
                "user@example.com",
                Uuid::now_v7().to_string().trim(),
                "12345",
            ),
            create_verify_2fa_request("user@example.com", "my_attempt_id", "12345"),
            create_verify_2fa_request("user@example.com", "my_attempt_id", ""),
            create_verify_2fa_request("user@example.com", "", "12345"),
        ]
    }

    #[rstest]
    #[tokio::test]
    async fn should_return_422_if_malformed_input(verify_2fa_requests: Vec<Verify2FARequest>) {
        for verify_2fa_request in verify_2fa_requests {
            // Arrange
            let app_state = create_app_state_with_mock(move |_, _, _, _| {});

            let request = ValidatedJson(verify_2fa_request);

            let cookie_jar = CookieJar::new();
            let response = verify_2fa_handler(State(app_state), cookie_jar, request)
                .await
                .into_response();

            assert!(response.status().is_client_error());
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
    #[tokio::test]
    async fn should_return_401_if_incorrect_attempt_id() {
        // Arrange - Extract and organize test variables
        let email = "user@example.com";
        let test_email = Email::try_from(email).unwrap();
        let code = "123451";
        let attempt_id = Uuid::now_v7().to_string();
        let wrong_attempt_id = "1".to_string();

        let verify_2fa_request = create_verify_2fa_request(email, &attempt_id, code);

        let app_state = create_app_state_with_mock(
            move |_,
                  _,
                  mock_standard2fa_store,
                  _| {
                mock_standard2fa_store
                    .expect_has_active_2fa_code()
                    .times(1)
                    .with(eq(test_email.clone()))
                    .returning(move |_| {
                        Ok(Some(Standard2FaInfo {
                            attempt_id: wrong_attempt_id.clone(),
                            code_2fa: code.to_string(),
                            expires_at: Utc::now(),
                        }))
                    });
            },
        );

        // Act
        let request = ValidatedJson(verify_2fa_request);
        let cookie_jar = CookieJar::new();
        let response = verify_2fa_handler(State(app_state), cookie_jar, request)
            .await
            .into_response();

        // Assert
        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn should_return_401_if_incorrect_code() {
        // Arrange - Extract and organize test variables
        let email = "user@example.com";
        let test_email = Email::try_from(email).unwrap();
        let code = "123451";
        let attempt_id = Uuid::now_v7().to_string();

        let verify_2fa_request = create_verify_2fa_request(email, &attempt_id, code);

        let app_state = create_app_state_with_mock(
            move |_,
                  _,
                  mock_standard2fa_store,
                  _| {
                mock_standard2fa_store
                    .expect_has_active_2fa_code()
                    .times(1)
                    .with(eq(test_email.clone()))
                    .returning(move |_| {
                        Ok(Some(Standard2FaInfo {
                            attempt_id: attempt_id.clone(),
                            code_2fa: "123456".to_string(),
                            expires_at: Utc::now(),
                        }))
                    });
            },
        );

        // Act
        let request = ValidatedJson(verify_2fa_request);
        let cookie_jar = CookieJar::new();
        let response = verify_2fa_handler(State(app_state), cookie_jar, request)
            .await
            .into_response();

        // Assert
        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn should_return_401_if_standard2fa_returns_with_404() {
        // Arrange - Extract and organize test variables
        let email = "user@example.com";
        let test_email = Email::try_from(email).unwrap();
        let code = "123451";
        let attempt_id = Uuid::now_v7().to_string();

        let verify_2fa_request = create_verify_2fa_request(email, &attempt_id, code);

        let app_state = create_app_state_with_mock(move |_, _, mock_standard2fa_store, _| {
            mock_standard2fa_store
                .expect_has_active_2fa_code()
                .times(1)
                .with(eq(test_email.clone()))
                .returning(move |_| {
                    Ok(Some(Standard2FaInfo {
                        attempt_id: attempt_id.clone(),
                        code_2fa: "123456".to_string(),
                        expires_at: Utc::now(),
                    }))
                });
        });

        // Act
        let request = ValidatedJson(verify_2fa_request);
        let cookie_jar = CookieJar::new();
        let response = verify_2fa_handler(State(app_state), cookie_jar, request)
            .await
            .into_response();

        // Assert
        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn should_return_200_if_correct_code() {
        // Arrange - Extract and organize test variables
        let email = "user@example.com";
        let test_email = Email::try_from(email).unwrap();
        let code = "123456";
        let attempt_id = Uuid::now_v7().to_string();

        let verify_2fa_request = create_verify_2fa_request(email, &attempt_id, code);

        let app_state = create_app_state_with_mock(move |_, _, mock_standard2fa_store, _| {
            mock_standard2fa_store
                .expect_has_active_2fa_code()
                .times(1)
                .with(eq(test_email.clone()))
                .returning(move |_| {
                    Ok(Some(Standard2FaInfo {
                        attempt_id: attempt_id.clone(),
                        code_2fa: code.to_string(),
                        expires_at: Utc::now() + Duration::minutes(5),
                    }))
                });

            mock_standard2fa_store
                .expect_verify_and_consume_2fa_code()
                .times(1)
                .with(eq(test_email.clone()), eq(code.to_string()))
                .returning(move |_, _| {
                    Ok(())
                });
        });

        // Act
        let request = ValidatedJson(verify_2fa_request);
        let cookie_jar = CookieJar::new();
        let response = verify_2fa_handler(State(app_state), cookie_jar, request)
            .await
            .into_response();

        // Assert
        assert!(response.status().is_success());
        assert_eq!(response.status(), StatusCode::OK);

        let response_headers = response.headers();
        assert!(response_headers.contains_key(SET_COOKIE));

        // Parse the Set-Cookie header
        let cookie_header = response_headers.get(SET_COOKIE).unwrap().to_str().unwrap();

        // Verify cookie attributes
        assert!(cookie_header.starts_with("jwt="));
        assert!(cookie_header.contains("; HttpOnly"));
        assert!(cookie_header.contains("; SameSite=Lax"));
        assert!(cookie_header.contains("; Path=/"));

        // Extract and validate the JWT token
        let token_part = cookie_header.split(';').next().unwrap();
        let token = token_part.strip_prefix("jwt=").unwrap();

        // Validate JWT structure (3 parts separated by dots)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    }
}
