use crate::api::error::AuthAPIError;
use crate::api::login::{LoginRequest, LoginResponse};
use crate::routes::helper::{map_validation_errors_to_response, ValidatedJson};
use crate::{utils, AppState};
use axum::extract::State;
use axum::http::header::{CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;
use tracing::{warn};
use validator::Validate;

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

    let user_state = &app_state.user_store;

    let password_validation_result = user_state
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
        Json(LoginResponse::new()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::login::LoginRequest;
    use crate::domain::data_stores::{MockBannedTokenStore, MockUserStore};
    use reqwest::header::SET_COOKIE;

    // Helper function to create app state with mock user store and banned token store
    fn create_app_state_with_mock<F>(setup: F) -> AppState
    where
        F: FnOnce(&mut MockUserStore, &mut MockBannedTokenStore),
    {
        let mut mock_user_store = MockUserStore::new();
        let mut mock_banned_token_store = MockBannedTokenStore::new();

        setup(&mut mock_user_store, &mut mock_banned_token_store);

        AppState {
            user_store: std::sync::Arc::new(tokio::sync::RwLock::new(mock_user_store)),
            banned_token_store: std::sync::Arc::new(tokio::sync::RwLock::new(mock_banned_token_store)),
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
    async fn test_login_handler() {
        // Arrange
        let _app_state = create_app_state_with_mock(|mock,_| {
            mock.expect_validate_user().returning(|_, _| Ok(()));
        });

        // Arrange
        let app_state = create_app_state_with_mock(|mock,_| {
            mock.expect_validate_user().returning(|_, _| Ok(()));
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
    }
}
