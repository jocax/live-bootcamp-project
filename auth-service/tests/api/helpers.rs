use auth_service::model::{
    LoginRequest, LogoutRequest, SignUpRequest, Verify2FARequest, VerifyTokenRequest,
};
use auth_service::Application;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub(crate) async fn get_random_email() -> String {
        //we use v7 due to the time support and natural order for database indexing
        format!("{}@example.com", Uuid::now_v7())
    }
}

impl TestApp {
    pub async fn new() -> Self {
        // Ensure TLS is disabled for tests
        std::env::set_var("TLS_ENABLED", "false");
        
        let app = Application::build("127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address());
        println!("Running on {:?}", address);

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(async move {
            app.run().await.expect("Failed to run app");
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let http_client = reqwest::Client::new();

        // Create new `TestApp` instance and return it
        TestApp {
            address,
            http_client,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        println!("GET {}", &self.address);
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }
    pub async fn post_signup(&self, signup: &SignUpRequest) -> reqwest::Response {
        println!("POST {}/api/signup", &self.address);
        self.http_client
            .post(&format!("{}/api/signup", &self.address))
            .json(&signup)
            .send()
            .await
            .expect("Failed to execute signup request.")
    }
    pub async fn post_signup_body<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/api/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute signup request.")
    }


    pub async fn post_login(&self, login_request: &LoginRequest) -> reqwest::Response {
        println!("POST {}/api/login", &self.address);
        self.http_client
            .post(&format!("{}/api/login", &self.address))
            .json(&login_request)
            .send()
            .await
            .expect("Failed to execute login request.")
    }

    pub async fn post_logout(&self, logout_request: &LogoutRequest) -> reqwest::Response {
        println!("POST {}/api/logout", &self.address);
        self.http_client
            .post(&format!("{}/api/logout", &self.address))
            .json(&logout_request)
            .send()
            .await
            .expect("Failed to execute logout request.")
    }

    pub async fn post_verify2fa(&self, verify_2fa_request: &Verify2FARequest) -> reqwest::Response {
        println!("POST {}/api/verify-2fa", &self.address);
        self.http_client
            .post(&format!("{}/api/verify-2fa", &self.address))
            .json(&verify_2fa_request)
            .send()
            .await
            .expect("Failed to execute verify-2fa request.")
    }

    pub async fn post_verify_token(
        &self,
        verify_token_request: &VerifyTokenRequest,
    ) -> reqwest::Response {
        println!("POST {}/api/verify-token", &self.address);
        self.http_client
            .post(&format!("{}/api/verify-token", &self.address))
            .json(&verify_token_request.get_token())
            .send()
            .await
            .expect("Failed to execute verify-token request.")
    }

}
