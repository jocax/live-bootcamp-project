use crate::api::{helpers, TestApp};
use auth_service::api::login::{Login2FaRequiredResponse, LoginRequest, LoginResponse};
use auth_service::domain::types::{Email, Password};
use auth_service::domain::user::User;
use auth_service::utils;
use auth_service::utils::constants::JWT_SECRET;
use serde::Serialize;
use serde_json::json;

#[test]
fn test_serialization() {
    #[derive(Serialize, Debug)]
    struct SimpleLogin {
        email: String,
        password: String,
    }

    let simple = SimpleLogin {
        email: "test@example.com".to_string(),
        password: "wrong_password_1234".to_string(),
    };

    let json = serde_json::to_string(&simple).unwrap();
    println!("Simple struct JSON: {}", json);
    // Should print: {"email":"test@example.com","password":"wrong_password_1234"}

    // Now test your actual struct
    let email = Email::try_from("test@example.com").unwrap();
    let login_request = LoginRequest::new(email, "wrong_password_1234".to_string());
    let json2 = serde_json::to_string(&login_request).unwrap();
    println!("LoginRequest JSON: {}", json2);
}

#[tokio::test]
async fn test_login() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let standard_2fa_code_store_type = helpers::create_standard_2fa_code_store_type();
    let stdout_email_client_type = helpers::create_stdout_email_client_type();

    let password_value = String::from("password123");
    let email = Email::try_from("test@example.com".to_string()).unwrap();
    let password = Password::try_from(password_value.clone()).unwrap();

    let user = User::new(email.clone(), password, false);

    user_store_type
        .write()
        .await
        .add_user(user.clone())
        .await
        .expect("Failed to add user");
    let app = TestApp::new(
        user_store_type,
        banned_token_store_type,
        standard_2fa_code_store_type,
        stdout_email_client_type,
    )
    .await;

    let login_request = LoginRequest::new(email, password_value);

    // Debug what serde_json produces
    let json_string = serde_json::to_string(&login_request).unwrap();
    println!("JSON being sent: {}", json_string);

    // Also check the struct itself
    println!("Password in struct: '{}'", login_request.get_password());

    let response = app.post_login(&login_request).await;
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
    assert!(cookie_str.starts_with("jwt="));
    assert!(cookie_str.contains("SameSite=Lax"));
}

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
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

    let unkown_request_body = json!({
        "field_name": "field_value"
    });

    let response = app.post_login_any_body(&unkown_request_body).await;
    assert_eq!(response.status().as_u16(), 422);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let standard_2fa_code_store_type = helpers::create_standard_2fa_code_store_type();
    let stdout_email_client_type = helpers::create_stdout_email_client_type();

    let password_value = String::from("password123");
    let email = Email::try_from("test@example.com".to_string()).unwrap();
    let password = Password::try_from(password_value.clone()).unwrap();

    let user = User::new(email.clone(), password, false);

    user_store_type
        .write()
        .await
        .add_user(user.clone())
        .await
        .expect("Failed to add user");
    let app = TestApp::new(
        user_store_type,
        banned_token_store_type,
        standard_2fa_code_store_type,
        stdout_email_client_type,
    )
    .await;

    let login_request = LoginRequest::new(email, "wrong_password_1234".to_string());

    let response = app.post_login(&login_request).await;
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let standard_2fa_code_store_type = helpers::create_standard_2fa_code_store_type();
    let stdout_email_client_type = helpers::create_stdout_email_client_type();

    let password_value = String::from("password123");
    let email = Email::try_from("test@example.com".to_string()).unwrap();
    let password = Password::try_from(password_value.clone()).unwrap();

    let user = User::new(email.clone(), password, false);

    user_store_type
        .write()
        .await
        .add_user(user.clone())
        .await
        .expect("Failed to add user");
    let app = TestApp::new(
        user_store_type,
        banned_token_store_type,
        standard_2fa_code_store_type,
        stdout_email_client_type,
    )
    .await;

    let random_email = Email::try_from("test@example.com".to_string()).unwrap();

    let login_body = LoginRequest::new(random_email, password_value);
    let response = app.post_login(&login_body.into()).await;

    assert_eq!(response.status().as_u16(), 200);

    let cookies = helpers::get_cookies(&response);

    let auth_cookie = cookies
        .get(utils::constants::JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let claims = helpers::decode_jwt(&auth_cookie.value_trimmed(), JWT_SECRET.as_bytes()).unwrap();
    println!("{:?}", claims);

    assert_eq!(claims.sub, "test@example.com");
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let standard_2fa_code_store_type = helpers::create_standard_2fa_code_store_type();
    let stdout_email_client_type = helpers::create_stdout_email_client_type();

    let password_value = String::from("password123");
    let email = &Email::try_from("test@example.com".to_string()).unwrap();
    let password = Password::try_from(password_value.clone()).unwrap();

    let user = User::new(email.clone(), password, true); //2fa enabled

    user_store_type
        .write()
        .await
        .add_user(user.clone())
        .await
        .expect("Failed to add user");
    let app = TestApp::new(
        user_store_type,
        banned_token_store_type,
        standard_2fa_code_store_type,
        stdout_email_client_type,
    )
    .await;

    let random_email = Email::try_from("test@example.com".to_string()).unwrap();

    let login_body = LoginRequest::new(random_email, password_value);
    let response = app.post_login(&login_body.into()).await;

    assert_eq!(response.status().as_u16(), 206);

    // Extract the body
    let text = response.text().await.unwrap();
    println!("Raw response: {}", text);
    let login_response: LoginResponse =
        serde_json::from_str(&text).expect("expected login response for 2fa enabled user");

    println!("Login response: {:?}", login_response);
}
