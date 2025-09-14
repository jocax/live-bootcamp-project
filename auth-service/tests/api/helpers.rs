use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use axum_extra::extract::cookie::Cookie;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use auth_service::api::login::LoginRequest;
use auth_service::api::logout::LogoutRequest;
use auth_service::api::signup::SignUpRequest;
use auth_service::api::verify_2fa::Verify2FARequest;
use auth_service::api::verify_token::VerifyTokenRequest;
use auth_service::{AppState, Application, BannedTokenStoreType, EmailClientType, Standard2FACodeStoreType, UserStoreType};
use uuid::Uuid;
use auth_service::domain::data_stores::{BannedTokenStore, Standard2FaStore, UserStore};
use auth_service::services::{HashMapBannedTokenStore, HashMapUserStore, StdoutEmailClient};
use reqwest::cookie::Jar;
use auth_service::domain::email_client::EmailClient;
use auth_service::services::data_stores::hashmap_2fa_code_store::HashMapStandard2FaStore;
use auth_service::utils::constants::JWT_SECRET;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
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
        format!("{}/api{}", self.address, endpoint)
    }

    //we use in the unit tests the same url as later in the deployment via docker compose and nginx
    // http://server:port/auth
    fn ui_url(&self, path: &str) -> String {
        format!("{}/{}", self.address, path)
    }
}

impl TestApp {
    pub async fn new(
        user_store: UserStoreType,
        banned_token_store: BannedTokenStoreType,
        standard_2fa_store: Standard2FACodeStoreType,
        email_client: EmailClientType,
    ) -> Self {

        let app_state = AppState::new(user_store, banned_token_store, standard_2fa_store, email_client);

        // Ensure TLS is disabled for tests
        std::env::set_var("TLS_ENABLED", "false");

        let app = Application::build(app_state, "127.0.0.1:0")
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

        let cookie_jar = Arc::new(Jar::default());

        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        // Create new `TestApp` instance and return it
        TestApp {
            address,
            cookie_jar,
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
        println!("POST {}", &url);
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
    pub async fn post_login_any_body<Body: serde::Serialize>(&self, body: &Body) -> reqwest::Response {
        let url = self.api_url("/login");
        println!("POST {}", &url);
        self.http_client
            .post(&url)
            .json(&body)
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
            .json(&verify_token_request)
            .send()
            .await
            .expect("Failed to execute verify-token request.")
    }
}

pub fn create_user_store_type() -> Arc<RwLock<dyn UserStore>> {
    Arc::new(RwLock::new(HashMapUserStore::default()))
}

pub fn create_banned_toke_store_type() -> Arc<RwLock<dyn BannedTokenStore>> {
    Arc::new(RwLock::new(HashMapBannedTokenStore::default()))
}

pub fn create_standard_2fa_code_store_type() -> Arc<RwLock<dyn Standard2FaStore>> {
    Arc::new(RwLock::new(HashMapStandard2FaStore::default()))
}

pub fn create_stdout_email_client_type() -> Arc<RwLock<dyn EmailClient>> {
    Arc::new(RwLock::new(StdoutEmailClient::default()))
}

pub fn get_cookies(response: &'_ reqwest::Response) -> HashMap<String, Cookie<'_>> {
    let mut cookies: HashMap<String, Cookie> = HashMap::new();
    for cookie_header in response.headers().get_all("set-cookie") {
                let cookie_str = cookie_header.to_str().unwrap();
        let cookie = Cookie::parse(cookie_str);
        if let Ok(cookie) = cookie {
            cookies.insert(cookie.name().to_string(), cookie);
        }
    }
    cookies
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelpersClaims {
    pub sub: String,  // subject (email in your case)
    pub exp: i64,     // expiration time
}

impl Display for HelpersClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn decode_jwt(token: &str, secret: &[u8]) -> Result<HelpersClaims, jsonwebtoken::errors::Error> {
    let validation = Validation::new(Algorithm::HS256);

    let token_data = decode::<HelpersClaims>(
        token,
        &DecodingKey::from_secret(secret),
        &validation
    )?;

    Ok(token_data.claims)
}

pub fn create_exp_from_date_time(date_time: chrono::DateTime<chrono::Utc>) -> i64 {
    date_time.timestamp()
}
pub fn create_claims(email: &str, exp: i64) -> HelpersClaims {
    HelpersClaims {
        sub: email.to_string(),
        exp
    }
}
pub fn create_token(claims: &HelpersClaims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()), //same secret as in production code
    )
}
