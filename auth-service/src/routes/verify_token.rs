use crate::api::error::AuthAPIError;
use crate::api::verify_token::{VerifyTokenRequest, VerifyTokenResponse};
use crate::routes::helper::{map_validation_errors_to_response, ValidatedJson};
use crate::utils;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use jsonwebtoken::errors::ErrorKind;
use validator::Validate;

pub async fn verify_token_handler(
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

    let token_validation = utils::auth::validate_token(token).await;

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
    use crate::utils::auth::Claims;
    use crate::utils::constants::JWT_SECRET;

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
        let email = &Email::try_from("user@example.com").unwrap();
        let cookie = utils::auth::generate_auth_cookie(email).unwrap();
        let token = cookie.value_trimmed();
        let login_request = create_verify_token_request(token);
        let request = ValidatedJson(login_request);

        let response = verify_token_handler(request).await.into_response();

        assert!(response.status().is_success())
    }

    #[tokio::test]
    async fn test_verify_token_handler_invalid_token_returns_422() {
        let verify_token_request = create_verify_token_request("invalid token");
        let request = ValidatedJson(verify_token_request);

        let response = verify_token_handler(request).await.into_response();

        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        )
    }

    #[tokio::test]
    async fn test_verify_token_handler_expired_token_returns_401() {
        let minus_three_hours =
            (Utc::now().timestamp() - Duration::hours(3).num_seconds()) as usize;

        let claims = &Claims {
            sub: "user@example.com".to_string(),
            exp: minus_three_hours,
        };

        let expired_token = create_token(claims).unwrap();
        let verify_token_request = create_verify_token_request(expired_token.as_str());
        let request = ValidatedJson(verify_token_request);

        let response = verify_token_handler(request).await.into_response();

        assert!(response.status().is_client_error());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        )
    }
}
