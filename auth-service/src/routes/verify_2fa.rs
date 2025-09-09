use axum::extract::State;
use axum::http::{StatusCode};
use axum::http::header::SET_COOKIE;
use axum::Json;
use axum::response::IntoResponse;
use validator::Validate;
use crate::api::error::AuthAPIError;
use crate::api::verify_2fa::{Verify2FARequest, Verify2FAResponse};
use crate::AppState;
use crate::routes::helper::{map_validation_errors_to_response, ValidatedJson};

pub async fn verify_2fa_handler(
    State(_app_state): State<AppState>,
    ValidatedJson(request): ValidatedJson<Verify2FARequest>,
) -> Result<impl IntoResponse, AuthAPIError> {

    // Validate the request
    let validation_result = request.validate();

    if validation_result.is_err() {
        return Err(map_validation_errors_to_response(
            validation_result.unwrap_err().to_owned(),
        ));
    }

    //jwt=your_token; HttpOnly; SameSite=Lax; Secure; Path=/
    Ok((
        StatusCode::OK,
        [(
            SET_COOKIE,
            "jwt=my-verified-token; Path=/; HttpOnly; SameSite=Lax",
        )],
        Json(Verify2FAResponse {}),
    )
        .into_response()
    )
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};
    use uuid::Uuid;
    use crate::domain::data_stores::{MockBannedTokenStore, MockStandard2FaStore, MockUserStore};
    use crate::domain::email_client::MockEmailClient;
    use crate::routes::helper::ValidatedJson;
    use super::*;

    // Helper function to create app state with mock user store and banned token store
    fn create_app_state_with_mock<F>(setup: F) -> AppState
    where
        F: FnOnce(&mut MockUserStore, &mut MockBannedTokenStore, &mut MockStandard2FaStore, &mut MockEmailClient) ,
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

    fn create_verify_2fa_request(email: &str, attempt_id: &str, code: &str) -> Verify2FARequest {
        Verify2FARequest::new(
            crate::domain::types::Email::try_from(email).unwrap(),
            attempt_id.to_string(),
            code.to_string(),
        )
    }

    #[fixture]
    fn verify_2fa_requests() -> Vec<Verify2FARequest> {
        vec![
            create_verify_2fa_request("user@example.com", "", ""),
            create_verify_2fa_request("user@example.com",  Uuid::now_v7().to_string().trim(), "12345"),
            create_verify_2fa_request("user@example.com", "my_attempt_id", "12345"),
            create_verify_2fa_request("user@example.com", "my_attempt_id", ""),
            create_verify_2fa_request("user@example.com", "", "12345"),
        ]
    }

    #[rstest]
    #[tokio::test]
    async fn should_return_422_if_malformed_input(verify_2fa_requests: Vec<Verify2FARequest>) {

        for verify_2fa_request in verify_2fa_requests {
            // Arrange
            let app_state = create_app_state_with_mock(move |_, _, _, _| {
            });

            let request = ValidatedJson(verify_2fa_request);

            let response = verify_2fa_handler(State(app_state), request)
                .await
                .into_response();

            assert!(response.status().is_client_error());
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }

    }

}
