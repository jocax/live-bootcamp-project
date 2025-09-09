use axum::extract::State;
use crate::api::error::AuthAPIError;
use crate::api::verify_token::{VerifyTokenRequest, VerifyTokenResponse};
use crate::routes::helper::{map_validation_errors_to_response, ValidatedJson};
use crate::{utils, AppState};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use jsonwebtoken::errors::ErrorKind;
use validator::Validate;

pub async fn verify_token_handler(
    State(app_state): State<AppState>,
    ValidatedJson(request): ValidatedJson<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the request
    let validation_result = request.validate();

    if validation_result.is_err() {
        return Err(map_validation_errors_to_response(
            validation_result.unwrap_err().to_owned(),
        ));
    }

    let token = request.get_token();

    let token_validation = utils::auth::validate_token(token, &app_state.banned_token_store).await;

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

    if token_validation.is_err() {
        let token_error = token_validation.unwrap_err();

        let status_code = match token_error.kind() {
            ErrorKind::ExpiredSignature => StatusCode::UNAUTHORIZED,
            ErrorKind::InvalidToken => StatusCode::BAD_REQUEST,
            ErrorKind::InvalidSignature => StatusCode::UNAUTHORIZED,
            ErrorKind::InvalidAlgorithm => StatusCode::BAD_REQUEST,
            ErrorKind::InvalidKeyFormat => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorKind::InvalidIssuer => StatusCode::UNAUTHORIZED,
            ErrorKind::InvalidAudience => StatusCode::FORBIDDEN,
            ErrorKind::ImmatureSignature => StatusCode::UNAUTHORIZED,
            ErrorKind::MissingRequiredClaim(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        };

        Ok((status_code, headers, Json(VerifyTokenResponse::new(false))).into_response())
    } else {
        Ok((
            StatusCode::OK,
            headers,
            Json(VerifyTokenResponse::new(true)),
        )
            .into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Email;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, EncodingKey};
    use crate::domain::data_stores::{MockBannedTokenStore, MockStandard2FaStore, MockUserStore};
    use crate::domain::email_client::MockEmailClient;
    use crate::utils::auth::Claims;
    use crate::utils::constants::JWT_SECRET;

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

    fn create_verify_token_request(token: &str) -> VerifyTokenRequest {
        VerifyTokenRequest::new(token.to_owned())
    }

    fn create_token(
        claims: &crate::utils::auth::Claims,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
        )
    }

    #[tokio::test]
    async fn test_verify_token_handler_valid_token_returns_200() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock_user, mock_banned, mock_2fa_code,_| {
            mock_user.expect_validate_user().returning(|_, _| Ok(()));

            // Expect the token not to be banned
            mock_banned.expect_is_banned()
                .times(1)
                .returning(|_| Ok(false));
            // Ensure banned token store is never called
            mock_banned
                .expect_ban_until_expiry()
                .never();
            mock_banned
                .expect_ban_with_ttl()
                .never();
            mock_2fa_code
                .expect_has_active_2fa_code()
                .never();
        });
        let email = &Email::try_from("user@example.com").unwrap();
        let cookie = utils::auth::generate_auth_cookie(email).unwrap();
        let token = cookie.value_trimmed();
        let login_request = create_verify_token_request(token);
        let request = ValidatedJson(login_request);

        let response = verify_token_handler(State(app_state), request).await.into_response();

        assert!(response.status().is_success())
    }

    #[tokio::test]
    async fn test_verify_token_handler_invalid_token_returns_422() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock_user, mock_banned, mock_2fa_code, _| {
            mock_user.expect_validate_user().returning(|_, _| Ok(()));

            // Ensure banned token store is never called
            mock_banned
                .expect_ban_until_expiry()
                .never();
            mock_banned
                .expect_ban_with_ttl()
                .never();
            mock_2fa_code
                .expect_has_active_2fa_code()
                .never();
        });
        let verify_token_request = create_verify_token_request("invalid token");
        let request = ValidatedJson(verify_token_request);

        let response = verify_token_handler(State(app_state), request).await.into_response();

        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        )
    }

    #[tokio::test]
    async fn test_verify_token_handler_expired_token_returns_401() {
        // Arrange
        let app_state = create_app_state_with_mock(|mock_user, mock_banned, mock_2fa_code, _| {
            mock_user.expect_validate_user().returning(|_, _| Ok(()));

            // Ensure banned token store is never called
            mock_banned
                .expect_ban_until_expiry()
                .never();
            mock_banned
                .expect_ban_with_ttl()
                .never();
            mock_2fa_code
                .expect_has_active_2fa_code()
                .never();
        });

        let minus_three_hours =
            (Utc::now().timestamp() - Duration::hours(3).num_seconds()) as usize;

        let claims = &Claims {
            sub: "user@example.com".to_string(),
            exp: minus_three_hours,
        };

        let expired_token = create_token(claims).unwrap();
        let verify_token_request = create_verify_token_request(expired_token.as_str());
        let request = ValidatedJson(verify_token_request);

        let response = verify_token_handler(State(app_state), request).await.into_response();

        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        )
    }
}
