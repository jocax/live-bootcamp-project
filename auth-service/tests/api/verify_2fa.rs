use crate::api::{helpers, TestApp};
use auth_service::api::verify_2fa::Verify2FARequest;
use auth_service::domain::types::Email;

#[tokio::test]
async fn test_verify_2fa() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let standard_2fa_code_store_type = helpers::create_standard_2fa_code_store_type();
    let stdout_email_client_type = helpers::create_stdout_email_client_type();
    let app = TestApp::new(
        user_store_type,
        banned_token_store_type,
        standard_2fa_code_store_type,
        stdout_email_client_type,
    )
    .await;

    let verify_2fa_request = Verify2FARequest::new(
        Email::try_from("user@example.com").unwrap(),
        "my_attempt_id_uuid".to_string(),
        "my-verify-token".to_string());

    let response = app.post_verify2fa(&verify_2fa_request).await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    // Get all Set-Cookie headers
    let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();

    // Check if any cookie was set
    assert!(
        !cookies.is_empty(),
        "Expected at least one cookie to be set"
    );

    // Check specific cookie
    let jwt_cookie = cookies
        .iter()
        .find(|cookie| cookie.to_str().unwrap().starts_with("jwt="))
        .expect("jwt cookie not found");

    let cookie_str = jwt_cookie.to_str().unwrap();
    assert!(cookie_str.contains("HttpOnly"));
    assert!(cookie_str.contains("Path=/"));
    assert!(cookie_str.contains("jwt=my-verified-token"));
    assert!(cookie_str.contains("SameSite=Lax"));
}
