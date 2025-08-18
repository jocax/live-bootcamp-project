use crate::model::{ErrorResponse, LogoutResponse, SignUpRequest, SignUpResponse, Verify2FAResponse, VerifyTokenResponse};
use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use axum::response::{ IntoResponse, Response};
use axum::Json;
use validator::Validate;

pub async fn signup_handler(Json(request): Json<SignUpRequest>) -> impl IntoResponse {

    // Validate the request
    if let Err(errors) = request.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {message: format!("Validation error: {:?}", errors)}),
        ).into_response();
    }

    Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .body(
            Json(SignUpResponse {
                message: "User created successfully!".to_string(),
            })
            .into_response()
            .into_body(),
        )
        .unwrap()
}

pub async fn login_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(SET_COOKIE, "jwt=myToken; Path=/; HttpOnly; SameSite=Lax")],
        Json(LogoutResponse {}),
    )
        .into_response()
}

pub async fn logout_handler() -> impl IntoResponse {
    //jwt=your_token; HttpOnly; SameSite=Lax; Secure; Path=/
    (
        StatusCode::OK,
        [(SET_COOKIE, "jwt=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure; Path=/")],
        Json(LogoutResponse {}),
    )
        .into_response()
}

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

pub async fn verify_token_handler() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Json(VerifyTokenResponse {}).into_response().into_body())
        .unwrap()
}
