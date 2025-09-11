use crate::api::error::AuthAPIError;
use crate::api::login::{Login2FaRequiredResponse, LoginRegularAuthResponse, LoginRequest, LoginResponse};
use crate::routes::helper::{map_user_store_error_to_response, map_validation_errors_to_response, ValidatedJson};
use crate::{utils, AppState, EmailClientType, Standard2FACodeStoreType};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;
use rand::distr::Alphanumeric;
use rand::{rng, Rng};
use tracing::{warn};
use validator::Validate;
use crate::domain::data_stores::{Standard2FaInfo};
use crate::domain::types::Email;

// Change the function signatures to use an explicit type
type LoginResponseType = (StatusCode, HeaderMap, CookieJar, Json<LoginResponse>);


pub async fn login_handler(
    State(app_state): State<AppState>,
    cookie_jar: CookieJar,
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


    let password_validation_result = app_state.user_store
        .read()
        .await
        .validate_user(email, password.as_ref());

    let password_validation = match password_validation_result {
        Ok(_) => true,
        Err(_) => false,
    };

    if !password_validation {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user_store_result = app_state.user_store.read().await.get_user(
        email
    ).await;

    if user_store_result.is_err() {
        return Err(map_user_store_error_to_response(user_store_result.unwrap_err()));
    }

    let user = user_store_result.unwrap();

    // Handle request based on user's 2FA configuration
    match user.get_requires2fa() {
        true => handle_2fa(cookie_jar, email, &app_state.standard_2fa_code_store, &app_state.email_client).await.map(|r| r.into_response()),
        false => handle_no_2fa(cookie_jar, &user.get_email()).map(|r| r.into_response()),
    }
}

async fn handle_2fa(cookie_jar: CookieJar, email: &Email, standard_2fa_code_store_type: &Standard2FACodeStoreType, email_client_type: &EmailClientType) -> Result<LoginResponseType, AuthAPIError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

    let store_read_guard = standard_2fa_code_store_type.read().await;
    let has_active_2fa_code = store_read_guard.has_active_2fa_code(email).await;
    drop(store_read_guard);

    if has_active_2fa_code.is_err() {
        return Err(AuthAPIError::UnexpectedError);
    }

    let stanadard_2fa_code_info_option = has_active_2fa_code.unwrap();

    match stanadard_2fa_code_info_option {
        //existing
        Some(Standard2FaInfo { attempt_id, code_2fa, ..  }) => {

            if let Some(value) = send_2fa_code_by_email(email, email_client_type, code_2fa).await {
                return value;
            }

            Ok((
                StatusCode::PARTIAL_CONTENT,
                headers,
                cookie_jar,
                Json::from(LoginResponse::TwoFactorAuth(
                    Login2FaRequiredResponse::new("2FA required".to_string(), attempt_id.to_string())
                )),
            ))
        }
        None => {
            let code = generate_random_code();
            let ttl_seconds = 60 * 5;
            let mut store_write_guard = standard_2fa_code_store_type.write().await;
            let store_result = store_write_guard.store_2fa_code(email, code.clone(), ttl_seconds).await;
            drop(store_write_guard);

            if store_result.is_err() {
                return Err(AuthAPIError::UnexpectedError);
            }

            if let Some(value) = send_2fa_code_by_email(email, email_client_type, code).await {
                return value;
            }

            Ok((
                StatusCode::PARTIAL_CONTENT,
                headers,
                cookie_jar,
                Json::from(LoginResponse::TwoFactorAuth(
                    Login2FaRequiredResponse::new("2FA required".to_string(), store_result.unwrap())
                )),
            ))
        }
    }
}

async fn send_2fa_code_by_email(email: &Email, email_client_type: &EmailClientType, code: String) -> Option<Result<LoginResponseType, AuthAPIError>> {
    let msg = format!("Sending 2FA code: {:?} by email to {:?}", code, email.as_ref());
    println!("{}", msg);

    if email_client_type.read().await.send_email(email, "Your 2FA code", format!("Your code: {:?}", code).as_str()).await.is_err() {
        return Some(Err(AuthAPIError::UnexpectedError));
    }
    None
}

fn handle_no_2fa(cookie_jar: CookieJar, email: &Email) -> Result<LoginResponseType, AuthAPIError> {
    let auth_cookie = match utils::auth::generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(error) => {
            warn!("Error generating auth cookie: {:?}", error);
            return Err(AuthAPIError::UnexpectedError);
        }
    };

    let updated_cookie_jar = cookie_jar.add(auth_cookie);

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

    Ok((
        StatusCode::OK,
        headers,
        updated_cookie_jar,
        Json::from(LoginResponse::RegularAuth(
            LoginRegularAuthResponse::new(true, "/app".to_string())
        ))
    ))
}

fn generate_random_code() -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect::<String>()
        .to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::login::LoginRequest;
    use crate::domain::data_stores::{MockBannedTokenStore, MockStandard2FaStore, MockUserStore};
    use crate::domain::types::{Email, Password};
    use crate::domain::user::User;
    use reqwest::header::SET_COOKIE;
    use mockall::predicate;
    use crate::domain::email_client::MockEmailClient;

    #[tokio::test]
    async fn test_generate_code() {

        let code = generate_random_code();

        // Verify generated code is 6 characters
        assert_eq!(code.len(), 6);

    }

    // Helper function to create app state with mock user store and banned token store
    fn create_app_state_with_mock<F>(setup: F) -> AppState
    where
        F: FnOnce(&mut MockUserStore, &mut MockBannedTokenStore, &mut MockStandard2FaStore, &mut MockEmailClient) ,
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

    // Helper function to create a login request
    fn create_login_request(email: &str, password: &str) -> LoginRequest {
        LoginRequest::new(
            crate::domain::types::Email::try_from(email).unwrap(),
            password.to_owned(),
        )
    }

    #[tokio::test]
    async fn test_login_handler_200_successful() {
        let user = User::new(
            Email::try_from("user@example.com").unwrap(),
            Password::try_from("password123").unwrap(),
            false,
        );

        // Arrange
        let app_state = create_app_state_with_mock(move |mock, _, _,_| {
            // Set up expectations on the mock that's provided by create_app_state_with_mock
            mock.expect_validate_user()
                .with(predicate::always(), predicate::always())
                .times(1)
                .returning(|_, _| Ok(()));

            mock.expect_get_user()
                .with(predicate::always())
                .times(1)
                .returning(move |_| Ok(user.clone()));
        });

        let login_request = create_login_request("user@example.com", "password123");
        let request = ValidatedJson(login_request);

        let cookie_jar = CookieJar::new();
        let response = login_handler(State(app_state), cookie_jar, request)
            .await
            .unwrap()
            .into_response();

        assert!(response.status().is_success());

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

        let response_body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let login_response: LoginResponse = serde_json::from_slice(&response_body).unwrap();
        assert_eq!(login_response, LoginResponse::RegularAuth(LoginRegularAuthResponse::new(true, "/app".to_string())));

    }

    #[tokio::test]
    async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
        let user = User::new(
            Email::try_from("user@example.com").unwrap(),
            Password::try_from("password123").unwrap(),
            true,
        );

        let standard_2fa_info = Standard2FaInfo {
            attempt_id: "my_attempt_id".to_string(),
            code_2fa: "123456".to_string(),
            expires_at: Default::default(),
        };

        // Arrange
        let app_state = create_app_state_with_mock(move |mock_user, _, mock_2fa_store,mock_email_client| {
            // Set up expectations on the mock that's provided by create_app_state_with_mock
            mock_user.expect_validate_user()
                .with(predicate::always(), predicate::always())
                .times(1)
                .returning(|_, _| Ok(()));

            mock_user.expect_get_user()
                .with(predicate::always())
                .times(1)
                .returning(move |_| Ok(user.clone()));

            mock_2fa_store.expect_has_active_2fa_code()
                .with(predicate::always())
                .times(1)
                .returning(move |_| Ok(Some(standard_2fa_info.clone())));

            mock_email_client.expect_send_email()
                .with(predicate::always(), predicate::always(), predicate::always())
                .times(1)
                .returning(|_, _, _| Ok(()));
        });

        let login_request = create_login_request("user@example.com", "password123");
        let request = ValidatedJson(login_request);
        let cookie_jar = CookieJar::new();

        let response = login_handler(State(app_state), cookie_jar, request)
            .await
            .unwrap()
            .into_response();

        assert!(response.status().is_success());
        assert_eq!(response.status(), 206);

        // Extract the body
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Deserialize into LoginResponse
        let login_response: LoginResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(login_response, LoginResponse::TwoFactorAuth(Login2FaRequiredResponse::new("2FA required".to_string(), "my_attempt_id".to_string())));

    }

}
