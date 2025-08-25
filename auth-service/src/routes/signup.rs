use crate::api::error::{AuthAPIError};
use crate::api::signup::{SignUpRequest, SignUpResponse};
use crate::domain::user::User;
use crate::routes::helper::{
    map_to_response, map_user_store_error_to_response, map_validation_errors_to_response,
};
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use validator::Validate;

pub async fn signup_handler(
    State(app_state): State<AppState>,
    Json(request): Json<SignUpRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the request
    let validation_result = request.validate();
    if validation_result.is_err() {
        return  Err(map_validation_errors_to_response(
            validation_result.unwrap_err().to_owned()));
    }

    let user = User::new(
        request.get_email(),
        request.get_password(),
        request.get_requires2fa(),
    );

    let mut user_store = app_state.user_store.write().await;

    let result = user_store.add_user(user).await;

    if result.is_ok() {
        Ok(map_to_response(
            StatusCode::CREATED,
            None,
            SignUpResponse::new("User created successfully!".to_string()),
        ))
    } else {
        Err(map_user_store_error_to_response(result.unwrap_err()))
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::data_stores::MockUserStore;
    use super::*;

    #[tokio::test]
    async fn test_signup_handler() {
        //create mock and use it with the expectation
        let mut mock_user_store = MockUserStore::new();
        mock_user_store.expect_add_user().returning(|_| Ok(()));

        let user_store = std::sync::Arc::new(tokio::sync::RwLock::new(
           mock_user_store
        ));
        let app_state = State(AppState { user_store });

        let signup_request = SignUpRequest::new(
            String::from("user@example.com"),
            String::from("myPasssword"),
            false,
        );

        let request = Json(signup_request);

        let response = signup_handler(app_state, request).await.into_response();
        assert!(response.status().is_success())
    }
}
