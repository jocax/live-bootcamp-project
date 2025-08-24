use crate::api::logout::LogoutResponse;
use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
pub async fn login_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(SET_COOKIE, "jwt=myToken; Path=/; HttpOnly; SameSite=Lax")],
        Json(LogoutResponse::new()).into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_login_handler() {
        let response = login_handler().await.into_response();
        assert!(response.status().is_success())
    }
}
