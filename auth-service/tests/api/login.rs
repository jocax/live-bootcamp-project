use serde_json::{json};
use auth_service::api::login::LoginRequest;
use auth_service::domain::types::{Email, Password};
use auth_service::domain::user::User;
use crate::api::{helpers, TestApp};

#[tokio::test]
async fn test_login() {

    let user_store_type = helpers::create_user_store_type();

    let password_value = String::from("password123");
    let email = Email::try_from("test@example.com".to_string()).unwrap();
    let password = Password::try_from(password_value.clone()).unwrap();

    let user = User::new(email.clone(), password, false);

    user_store_type.write().await.add_user(user.clone()).await.expect("Failed to add user");
    let app = TestApp::new(user_store_type).await;

    let login_request = LoginRequest::new(
       email,
        password_value
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
async fn should_return_422_if_malformed_credentials() {

    let user_store_type = helpers::create_user_store_type();
    let app = TestApp::new(user_store_type).await;

    let unkown_request_body = json!({
        "field_name": "field_value"
    });

    let response = app.post_login_any_body(&unkown_request_body).await;
    assert_eq!(response.status().as_u16(), 422);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");

}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {

    let user_store_type = helpers::create_user_store_type();

    let password_value = String::from("password123");
    let email = Email::try_from("test@example.com".to_string()).unwrap();
    let password = Password::try_from(password_value.clone()).unwrap();

    let user = User::new(email.clone(), password, false);

    user_store_type.write().await.add_user(user.clone()).await.expect("Failed to add user");
    let app = TestApp::new(user_store_type).await;

    let login_request = LoginRequest::new(
        email,
        "wrong_passsword_123".to_string()
    );

    let response = app.post_login(&login_request).await;
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
    
}
