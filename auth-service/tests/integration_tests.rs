mod api;

use api::TestApp;
use auth_service::model::{LoginRequest, LoginResponse, LogoutRequest, SignUpRequest, Verify2FARequest, VerifyTokenRequest};

// Tokio's test macro is used to run the test in an async environment
#[tokio::test]
async fn root_returns_auth_ui() {
    let app = TestApp::new().await;

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

#[tokio::test]
async fn test_signup() {
    let app = TestApp::new().await;

    let signup_request = SignUpRequest::new(
        "test@example.com".to_string(),
        "password123".to_string(),
        false,
    );

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
}

#[tokio::test]
async fn test_login() {
    let app = TestApp::new().await;

    let login_request = LoginRequest::new(
        "test@example.com".to_string(),
        "password123".to_string()
    );

    let response = app.post_login(&login_request).await;
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
    assert!(cookie_str.contains("jwt=myToken"));
    assert!(cookie_str.contains("SameSite=Lax"));
}

#[tokio::test]
async fn test_logout() {
    let app = TestApp::new().await;

    let logout_request = LogoutRequest::new(
        "my-token".to_string(),
    );

    let response = app.post_logout(&logout_request).await;
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
    assert!(cookie_str.contains("jwt="));
    assert!(cookie_str.contains("SameSite=Lax"));
    assert!(cookie_str.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
}

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


#[tokio::test]
async fn test_verify_token() {
    let app = TestApp::new().await;

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
