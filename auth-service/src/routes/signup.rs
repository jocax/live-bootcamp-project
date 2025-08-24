use axum::extract::State;
use axum::http::{StatusCode};
use axum::Json;
use axum::response::IntoResponse;
use validator::Validate;
use crate::api::error::ErrorResponse;
use crate::api::signup::{SignUpRequest, SignUpResponse};
use crate::AppState;
use crate::domain::user::User;
use crate::routes::helper::{map_error_to_response, map_to_response};

pub async fn signup_handler(State(app_state): State<AppState>, Json(request): Json<SignUpRequest>) -> impl IntoResponse {
    // Validate the request
    if let Err(errors) = request.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new( format!("Validation error: {:?}", errors))
            )).into_response()
    }

    let user = User::new(request.get_email(), request.get_password(), request.get_requires2fa());
    let mut user_store = app_state.user_store.write().await;

    let result = user_store.add_user(user);

    if result.is_ok() {
        map_to_response(StatusCode::CREATED, None, SignUpResponse::new(
            "User created successfully!".to_string(),
        )).into_response()
    } else {
        map_error_to_response(result.unwrap_err()).into_response()
    }

}

#[cfg(test)]
mod tests {
    use crate::UserStoreType;
    use super::*;

    #[tokio::test]
    async fn test_signup_handler() {

        let user_store = UserStoreType::default();
        let app_state = State(AppState { user_store });

        let signup_request = SignUpRequest::new(
            String::from("user@example.com"),
            String::from("myPasssword"),
            false
        );

        let request = Json(signup_request);

        let response = signup_handler(app_state, request).await.into_response();
        assert!(response.status().is_success())
    }
}
