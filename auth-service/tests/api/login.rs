use auth_service::model::LoginRequest;
use crate::api::TestApp;

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
