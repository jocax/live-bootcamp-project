use axum::http::{StatusCode};
use axum::http::header::SET_COOKIE;
use axum::Json;
use axum::response::IntoResponse;
use crate::api::verify_2fa::Verify2FAResponse;

pub async fn verify_2fa_handler() -> impl IntoResponse {
    //jwt=your_token; HttpOnly; SameSite=Lax; Secure; Path=/
    (
        StatusCode::OK,
        [(
            SET_COOKIE,
            "jwt=my-verified-token; Path=/; HttpOnly; SameSite=Lax",
        )],
        Json(Verify2FAResponse {}),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_verify_2fa_handler() {
        let response = verify_2fa_handler().await.into_response();
        assert!(response.status().is_success())
    }

}
