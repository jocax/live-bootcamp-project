use auth_service::model::{
    LoginRequest, LogoutRequest, SignUpRequest, Verify2FARequest, VerifyTokenRequest,
};
use auth_service::Application;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app = Application::build("127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());
        println!("Running on {:?}", address);

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

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
        println!("POST {}/signup", &self.address);
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(&signup)
            .send()
            .await
            .expect("Failed to execute signup request.")
    }

    pub async fn post_login(&self, login_request: &LoginRequest) -> reqwest::Response {
        println!("POST {}/login", &self.address);
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(&login_request)
            .send()
            .await
            .expect("Failed to execute login request.")
    }

    pub async fn post_logout(&self, logout_request: &LogoutRequest) -> reqwest::Response {
        println!("POST {}/logout", &self.address);
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .json(&logout_request)
            .send()
            .await
            .expect("Failed to execute logout request.")
    }

    pub async fn post_verify2fa(&self, verify_2fa_request: &Verify2FARequest) -> reqwest::Response {
        println!("POST {}/verify-2fa", &self.address);
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(&verify_2fa_request)
            .send()
            .await
            .expect("Failed to execute verify-2fa request.")
    }

    pub async fn post_verify_token(
        &self,
        verify_token_request: &VerifyTokenRequest,
    ) -> reqwest::Response {
        println!("POST {}/verify-token", &self.address);
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .json(&verify_token_request.get_token())
            .send()
            .await
            .expect("Failed to execute verify-token request.")
    }
}
