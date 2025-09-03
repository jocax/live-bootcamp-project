use auth_service::api::verify_token::VerifyTokenRequest;
use crate::api::{helpers, TestApp};

#[tokio::test]
async fn test_verify_token() {
    let user_store_type = helpers::create_user_store_type();
    let app = TestApp::new(user_store_type).await;

    let verify_token_request = VerifyTokenRequest::new(
        "my-verify-token".to_string(),
    );

    let response = app.post_verify_token(&verify_token_request).await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");

    // Get all Set-Cookie headers
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .collect();

    // Check if any cookie was set
    assert!(cookies.is_empty(), "Expected no cookie to be set");

}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    todo!()
}

