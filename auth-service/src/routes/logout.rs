use crate::api::logout::{LogoutRequest, LogoutResponse};
use crate::routes::helper::ValidatedJson;
use crate::utils::constants::JWT_COOKIE_NAME;
use crate::{utils, AppState};
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;

pub async fn logout_handler(
    State(app_state): State<AppState>,
    cookie_jar: CookieJar,
    ValidatedJson(_request): ValidatedJson<LogoutRequest>,
) -> impl IntoResponse {
    let jwt_token = cookie_jar.get(JWT_COOKIE_NAME).to_owned();

    if jwt_token.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Json(LogoutResponse {}),
        )
            .into_response();
    }

    let token_value = match jwt_token {
        Some(token) => token.value().to_string(),
        None => "".to_string(),
    };

    let token_valid = utils::auth::validate_token(token_value.as_str(), &app_state.banned_token_store).await;

    match token_valid {
        Ok(claims) => {
            // Add token to banned store
            let mut banned_store = app_state.banned_token_store.write().await;
            let _ = banned_store.ban_until_expiry(&token_value, claims.exp as i64 as usize).await;
            drop(banned_store);
            (StatusCode::OK,
               [(
                   SET_COOKIE,
                   "jwt=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure; Path=/",
               )],
               Json(LogoutResponse {})
            ).into_response()
        }
        Err(_) => {
            (StatusCode::UNAUTHORIZED,
               HeaderMap::new(),
               Json(LogoutResponse {})
            ).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate;
    use super::*;
    use crate::domain::data_stores::{MockBannedTokenStore, MockStandard2FaStore, MockUserStore};
    use crate::domain::types::Email;
    use crate::AppState;
    use crate::domain::email_client::MockEmailClient;

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

    #[tokio::test]
    async fn test_logout_handler_no_token_return_400() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock_user, mock_banned, _, _| {
            mock_user.expect_validate_user().returning(|_, _| Ok(()));

            // Ensure banned token store is never called
            mock_banned
                .expect_ban_until_expiry()
                .never();
            mock_banned
                .expect_ban_with_ttl()
                .never();
        });

        let cookie_jar = CookieJar::new();
        let logout_request = LogoutRequest {};

        let response = logout_handler(State(app_state), cookie_jar, ValidatedJson(logout_request))
            .await
            .into_response();
        assert!(response.status().is_client_error());
        assert_eq!(response.status().as_u16(), 400)
    }

    #[tokio::test]
    async fn test_logout_handler_bad_token_return_401() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock_user, mock_banned, _,_| {
            mock_user.expect_validate_user().returning(|_, _| Ok(()));

            // Ensure banned token store is never called
            mock_banned
                .expect_ban_until_expiry()
                .never();
            mock_banned
                .expect_ban_with_ttl()
                .never();
        });

        use axum_extra::extract::cookie::{Cookie, CookieJar};

        let cookie_jar = CookieJar::new();

        let cookie = Cookie::build((JWT_COOKIE_NAME, "bad_token"))
            .domain("example.com")
            .path("/")
            .secure(true)
            .http_only(true);

        let updated_cookie_jar = cookie_jar.add(cookie);

        let response = logout_handler(
            State(app_state),
            updated_cookie_jar,
            ValidatedJson(LogoutRequest {}),
        )
        .await
        .into_response();

        assert!(response.status().is_client_error());
        assert_eq!(response.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn test_logout_handler_valid_token_return_200() {
        // Arrange
        let email = &Email::try_from("user@example.com").unwrap();
        let cookie = utils::auth::generate_auth_cookie(email).unwrap();
        let token_value = cookie.value().to_string();

        let app_state = create_app_state_with_mock(|mock_user, mock_banned, _, _| {
            mock_user.expect_validate_user().returning(|_, _| Ok(()));

            // Expect the token to be banned
            mock_banned.expect_is_banned()
                .with(predicate::eq(token_value.clone()))
                .times(1)
                .returning(|_| Ok(false));

            mock_banned
                .expect_ban_until_expiry()
                .with(
                    predicate::eq(token_value.clone()),
                    predicate::always() // We can't predict the exact expiry time
                )
                .times(1)
                .returning(|_, _| Ok(()));
        });

        use axum_extra::extract::cookie::CookieJar;

        let cookie_jar = CookieJar::new();
        let updated_cookie_jar = cookie_jar.add(cookie);

        let response = logout_handler(
            State(app_state),
            updated_cookie_jar,
            ValidatedJson(LogoutRequest {}),
        )
            .await
            .into_response();

        assert!(response.status().is_success());
        assert_eq!(response.status().as_u16(), 200);

        // Check that the response includes a cookie deletion header
        let headers = response.headers();
        assert!(headers.contains_key("set-cookie"));
        let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(cookie_header.contains("jwt="));
        assert!(cookie_header.contains("Expires=Thu, 01 Jan 1970"));
    }

    #[tokio::test]
    async fn test_logout_handler_valid_token_banned_store_error_unexpected_error() {
        // Test case where banned store returns an error
        let email = &Email::try_from("user@example.com").unwrap();
        let cookie = utils::auth::generate_auth_cookie(email).unwrap();
        let token_value = cookie.value().to_string();

        let app_state = create_app_state_with_mock(|mock_user, mock_banned, _,_| {
            mock_user.expect_validate_user().returning(|_, _| Ok(()));

            mock_banned.expect_is_banned()
                .with(predicate::eq(token_value.clone()))
                .times(1)
                .returning(|_| Ok(false));


            // Simulate banned store error
            mock_banned
                .expect_ban_until_expiry()
                .with(
                    predicate::eq(token_value.clone()),
                    predicate::always()
                )
                .times(1)
                .returning(|_, _| Err(crate::domain::data_stores::BannedTokenStoreError::UnexpectedError));
        });

        use axum_extra::extract::cookie::CookieJar;

        let cookie_jar = CookieJar::new();
        let updated_cookie_jar = cookie_jar.add(cookie);

        let response = logout_handler(
            State(app_state),
            updated_cookie_jar,
            ValidatedJson(LogoutRequest {}),
        )
            .await
            .into_response();

        // Even if banned store fails, logout should still succeed
        assert!(response.status().is_success());
        assert_eq!(response.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn test_logout_handler_valid_token_banned_store_error_token_not_valid_anymore_error() {
        // Test case where banned store returns an error
        let email = &Email::try_from("user@example.com").unwrap();
        let cookie = utils::auth::generate_auth_cookie(email).unwrap();
        let token_value = cookie.value().to_string();

        let app_state = create_app_state_with_mock(|mock_user, mock_banned, _, _| {
            mock_user.expect_validate_user().returning(|_, _| Ok(()));

            mock_banned.expect_is_banned()
                .with(predicate::eq(token_value.clone()))
                .times(1)
            .returning(|_| Ok(true));

        });

        use axum_extra::extract::cookie::CookieJar;

        let cookie_jar = CookieJar::new();
        let updated_cookie_jar = cookie_jar.add(cookie);

        let response = logout_handler(
            State(app_state),
            updated_cookie_jar,
            ValidatedJson(LogoutRequest {}),
        )
            .await
            .into_response();

        // Even if banned store fails, logout should still succeed
        assert!(response.status().is_client_error());
        assert_eq!(response.status().as_u16(), 401);
    }
}

//banned_store.ban_until_expiry(&token_value, claims.exp as i64 as usize).await;
