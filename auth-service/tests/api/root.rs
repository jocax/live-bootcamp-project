use crate::api::{helpers, TestApp};

#[tokio::test]
async fn root_returns_auth_ui() {
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

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
}
