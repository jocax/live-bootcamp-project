use auth_service::{AppState, Application, UserStoreType};
use uuid::Uuid;
use auth_service::api::login::LoginRequest;
use auth_service::api::logout::LogoutRequest;
use auth_service::api::signup::SignUpRequest;
use auth_service::api::verify_2fa::Verify2FARequest;
use auth_service::api::verify_token::VerifyTokenRequest;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub(crate) async fn get_random_email() -> String {
        //we use v7 due to the time support and natural order for database indexing
        format!("{}@example.com", Uuid::now_v7())
    }
    //we use in the unit tests the same url as later in the deployment via docker compose and nginx
    //http://server:port/auth/api
    fn api_url(&self, endpoint: &str) -> String {
        format!("{}/auth/api{}", self.address, endpoint)
    }

    //we use in the unit tests the same url as later in the deployment via docker compose and nginx
    // http://server:port/auth
    fn ui_url(&self, path: &str) -> String {
        format!("{}/auth{}", self.address, path)
    }
}

impl TestApp {
    pub async fn new() -> Self {

        let user_store = UserStoreType::default();
        let app_state = AppState::new(user_store);
        
        // Ensure TLS is disabled for tests
        std::env::set_var("TLS_ENABLED", "false");

        let app = Application::build(app_state,"127.0.0.1:0")
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
            http_client: http_client,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        let url = self.ui_url(""); // Try without trailing slash first
        println!("GET {}", &url);
        self.http_client
            .get(&url)
            .send()
            .await
            .expect("Failed to execute request.")
    }
    pub async fn post_signup(&self, signup: &SignUpRequest) -> reqwest::Response {
        let url = self.api_url("/signup");
        println!("POST {}",&url);
        self.http_client
            .post(url)
            .json(&signup)
            .send()
            .await
            .expect("Failed to execute signup request.")
    }
    pub async fn post_signup_body<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        let url = self.api_url("/signup");
        self.http_client
            .post(&url)
            .json(body)
            .send()
            .await
            .expect("Failed to execute signup request.")
    }


    pub async fn post_login(&self, login_request: &LoginRequest) -> reqwest::Response {
        let url = self.api_url("/login");
        println!("POST {}", &url);
        self.http_client
            .post(&url)
            .json(&login_request)
            .send()
            .await
            .expect("Failed to execute login request.")
    }

    pub async fn post_logout(&self, logout_request: &LogoutRequest) -> reqwest::Response {
        let url = self.api_url("/logout");
        println!("POST {}", &url);
        self.http_client
            .post(&url)
            .json(&logout_request)
            .send()
            .await
            .expect("Failed to execute logout request.")
    }

    pub async fn post_verify2fa(&self, verify_2fa_request: &Verify2FARequest) -> reqwest::Response {
        let url = self.api_url("/verify-2fa");
        println!("POST {}", &url);
        self.http_client
            .post(&url)
            .json(&verify_2fa_request)
            .send()
            .await
            .expect("Failed to execute verify-2fa request.")
    }

    pub async fn post_verify_token(
        &self,
        verify_token_request: &VerifyTokenRequest,
    ) -> reqwest::Response {
        let url = self.api_url("/verify-token");
        println!("POST {}", &url);
        self.http_client
            .post(&url)
            .json(&verify_token_request.get_token())
            .send()
            .await
            .expect("Failed to execute verify-token request.")
    }

}
