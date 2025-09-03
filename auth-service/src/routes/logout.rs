use axum::http::{HeaderMap, StatusCode};
use axum::http::header::SET_COOKIE;
use axum::Json;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use crate::api::logout::{LogoutRequest, LogoutResponse};
use crate::routes::helper::ValidatedJson;
use crate::utils;
use crate::utils::constants::JWT_COOKIE_NAME;

pub async fn logout_handler(
    cookie_jar: CookieJar,
    ValidatedJson(_request): ValidatedJson<LogoutRequest>,
) -> impl IntoResponse {

    let jwt_token = cookie_jar.get(JWT_COOKIE_NAME).to_owned();

    if jwt_token.is_none() {
         return (
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Json(LogoutResponse {}),
        ).into_response()
    }

    let token_value = match jwt_token {
        Some(token) => token.value().to_string(),
        None => "".to_string(),
    };

    let token_valid  = utils::auth::validate_token(token_value.as_str()).await;

    match token_valid {
        Ok(_) => {
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
    use crate::domain::types::Email;
    use super::*;
    #[tokio::test]
    async fn test_logout_handler_no_token_return_400()  {

        let cookie_jar = CookieJar::new();
        let logout_request = LogoutRequest {};

        let response = logout_handler(cookie_jar, ValidatedJson(logout_request)).await.into_response();
        assert!(response.status().is_client_error());
        assert_eq!(response.status().as_u16(), 400)
    }

    #[tokio::test]
    async fn test_logout_handler_bad_token_return_401()  {
        use axum_extra::extract::cookie::{Cookie, CookieJar};

        let cookie_jar = CookieJar::new();

        let cookie = Cookie::build((JWT_COOKIE_NAME, "bad_token"))
            .domain("example.com")
            .path("/")
            .secure(true)
            .http_only(true);

        let updated_cookie_jar = cookie_jar.add(cookie);

        let response = logout_handler(updated_cookie_jar,
            ValidatedJson(LogoutRequest {})
        )
            .await
            .into_response();

        assert!(response.status().is_client_error());
        assert_eq!(response.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn test_logout_handler_valid_token_return_200()  {
        use axum_extra::extract::cookie::{CookieJar};

        let cookie_jar = CookieJar::new();

        let email = &Email::try_from("user@example.com").unwrap();
        let cookie = utils::auth::generate_auth_cookie(
            email
        ).unwrap();

        let updated_cookie_jar = cookie_jar.add(cookie);

        let response = logout_handler(updated_cookie_jar,
                                      ValidatedJson(LogoutRequest {})
        )
            .await
            .into_response();

        assert!(response.status().is_success());
        assert_eq!(response.status().as_u16(), 200);
    }
}
