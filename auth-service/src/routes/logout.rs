use axum::http::{StatusCode};
use axum::http::header::SET_COOKIE;
use axum::Json;
use axum::response::IntoResponse;
use crate::api::logout::LogoutResponse;
pub async fn logout_handler() -> impl IntoResponse {
    //jwt=your_token; HttpOnly; SameSite=Lax; Secure; Path=/
    (
        StatusCode::OK,
        [(
            SET_COOKIE,
            "jwt=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure; Path=/",
        )],
        Json(LogoutResponse {}),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_logout_handler() {
        let response = logout_handler().await.into_response();
        assert!(response.status().is_success())
    }
}
