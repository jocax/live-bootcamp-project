use reqwest::Url;
use auth_service::api::logout::LogoutRequest;
use auth_service::domain::types::Email;
use auth_service::utils;
use auth_service::utils::constants::JWT_COOKIE_NAME;
use crate::api::{helpers, TestApp};


#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let app = TestApp::new(user_store_type, banned_token_store_type).await;

    let logout_request = LogoutRequest::new();

    let response = app.post_logout(&logout_request).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let app = TestApp::new(user_store_type, banned_token_store_type).await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let logout_request = LogoutRequest::new();

    let response = app.post_logout(&logout_request).await;
    assert_eq!(response.status().as_u16(), 401);

}

#[tokio::test]
async fn should_return_200_valid_token() {
    let user_store_type = helpers::create_user_store_type();
    let banned_token_store_type = helpers::create_banned_toke_store_type();
    let app = TestApp::new(user_store_type, banned_token_store_type).await;

    let email = &Email::try_from("user@example.com").unwrap();
    let cookie = utils::auth::generate_auth_cookie(email).unwrap();
    let value_trimmed = cookie.value_trimmed();

    let cookie = format!("{}={}; HttpOnly; SameSite=Lax; Secure; Path=/", JWT_COOKIE_NAME, value_trimmed);
    let url = &"http://127.0.0.1".parse::<Url>().unwrap();

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        cookie.as_str(),
        url,
    );

    let logout_request = LogoutRequest::new();

    let response = app.post_logout(&logout_request).await;
    assert_eq!(response.status().as_u16(), 200);


}
