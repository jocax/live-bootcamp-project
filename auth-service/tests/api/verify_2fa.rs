use auth_service::model::Verify2FARequest;
use crate::api::TestApp;

#[tokio::test]
async fn test_verify_2fa() {
    let app = TestApp::new().await;

    let verify_2fa_request = Verify2FARequest::new(
        "my-verify-token".to_string(),
    );

    let response = app.post_verify2fa(&verify_2fa_request).await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");

    // Get all Set-Cookie headers
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .collect();

    // Check if any cookie was set
    assert!(!cookies.is_empty(), "Expected at least one cookie to be set");

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
