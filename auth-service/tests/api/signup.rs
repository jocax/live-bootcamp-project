use auth_service::api::error::ErrorResponse;
use auth_service::api::signup::SignUpRequest;
use crate::api::TestApp;

#[tokio::test]
async fn signup_should_return_201() {
    let app = TestApp::new().await;

    let signup_request = SignUpRequest::new(
        "test@example.com".to_string(),
        "password123".to_string(),
        false,
    );

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 201);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn should_return_422_if_malformed_input_json() {
    let app = TestApp::new().await;

    let random_email = TestApp::get_random_email().await;

    let test_cases = [
        serde_json::json!({
            "email": random_email,
            "requires2fa": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup_body(&test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422, //here content not valid and can not be transformed to entity -> generates a 422
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_400_if_malformed_input_entity() {
    let app = TestApp::new().await;

    let test_cases = [
        SignUpRequest::new("user@example@".to_string(), "password123".to_string(), false),
        SignUpRequest::new("bad_email_format".to_string(), "password123".to_string(), false),
        SignUpRequest::new("user@example.com".to_string(), "1234567".to_string(), false),
        SignUpRequest::new("user@example.com".to_string(), "".to_string(), false)
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(&test_case).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", test_case);

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response.json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .get_error(),
            "Invalid format"
        )
    }

}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {

    let app = TestApp::new().await;

    let signup_request = SignUpRequest::new(
        "test@example.com".to_string(),
        "password123".to_string(),
        false,
    );

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 201);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 409);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    assert_eq!(
        response.json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .get_error(),
        "User already exists"
    )

}
