use axum::http::{Response, StatusCode};
use axum::Json;
use axum::response::IntoResponse;
use crate::api::verify_token::VerifyTokenResponse;

pub async fn verify_token_handler() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Json(VerifyTokenResponse::new(true)).into_response().into_body())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_verify_token_handler() {
        let response = verify_token_handler().await.into_response();
        assert!(response.status().is_success())
    }
}

