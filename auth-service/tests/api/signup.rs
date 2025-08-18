use auth_service::model::SignUpRequest;
use crate::api::TestApp;

#[tokio::test]
async fn test_signup() {
    let app = TestApp::new().await;

    let signup_request = SignUpRequest::new(
        "test@example.com".to_string(),
        "password123".to_string(),
        false,
    );

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 201);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
}
