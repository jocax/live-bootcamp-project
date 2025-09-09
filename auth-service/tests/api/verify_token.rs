use crate::api::{helpers, TestApp};
use auth_service::api::verify_token::VerifyTokenRequest;
use auth_service::domain::types::{Email, Password};
use auth_service::domain::user::User;
use chrono::{Duration, Utc};

#[tokio::test]
async fn test_verify_token() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let standard_2fa_code_store_type = helpers::create_standard_2fa_code_store_type();
    let stdout_email_client_type = helpers::create_stdout_email_client_type();

    let email = Email::try_from("user@example.com".to_string()).unwrap();
    let password = Password::try_from("password123".to_string()).unwrap();
    let user = User::new(email, password, false);
    let store = user_store_type.write().await.add_user(user).await;

    assert!(store.is_ok(), "Expected user to be added to the store");

    let time = Utc::now() + Duration::seconds(60);
    let exp = helpers::create_exp_from_date_time(time);
    let claims = &helpers::create_claims("user@example.com", exp);
    let token = helpers::create_token(claims).unwrap();

    let app = TestApp::new(
        user_store_type,
        banned_token_store_type,
        standard_2fa_code_store_type,
        stdout_email_client_type,
    )
    .await;

    let verify_token_request = VerifyTokenRequest::new(token.clone());

    let response = app.post_verify_token(&verify_token_request).await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    // Get all Set-Cookie headers
    let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();

    // Check if any cookie was set
    assert!(cookies.is_empty(), "Expected no cookie to be set");
}

#[tokio::test]
async fn should_return_401_if_malformed_input_token_has_expired() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let standard_2fa_code_store_type = helpers::create_standard_2fa_code_store_type();
    let stdout_email_client_type = helpers::create_stdout_email_client_type();

    let email = Email::try_from("user@example.com".to_string()).unwrap();
    let password = Password::try_from("password123".to_string()).unwrap();
    let user = User::new(email, password, false);
    let store = user_store_type.write().await.add_user(user).await;

    assert!(store.is_ok(), "Expected user to be added to the store");

    let time = Utc::now() + Duration::seconds(60);
    let exp = helpers::create_exp_from_date_time(time);
    let claims = &helpers::create_claims("user@example.com", exp);
    let token = helpers::create_token(claims).unwrap();

    let app = TestApp::new(
        user_store_type,
        banned_token_store_type,
        standard_2fa_code_store_type,
        stdout_email_client_type
    )
    .await;

    let verify_token_request =
        VerifyTokenRequest::new(token.clone() + "_appended_to_token_to_make_it_malformed");

    let response = app.post_verify_token(&verify_token_request).await;
    assert!(response.status().is_client_error());
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    // Get all Set-Cookie headers
    let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();

    // Check if any cookie was set
    assert!(cookies.is_empty(), "Expected no cookie to be set");
}

#[tokio::test]
async fn should_return_400_if_malformed_input_token_has_expired() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let standard_2fa_code_store_type = helpers::create_standard_2fa_code_store_type();
    let stdout_email_client_type = helpers::create_stdout_email_client_type();

    let app = TestApp::new(
        user_store_type,
        banned_token_store_type,
        standard_2fa_code_store_type,
        stdout_email_client_type
    )
    .await;

    let verify_token_request = VerifyTokenRequest::new("token_to_make_it_malformed".to_string());

    let response = app.post_verify_token(&verify_token_request).await;
    assert!(response.status().is_client_error());
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    // Get all Set-Cookie headers
    let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();

    // Check if any cookie was set
    assert!(cookies.is_empty(), "Expected no cookie to be set");
}
