pub mod api;
pub mod domain;
mod routes;
pub mod services;
pub mod utils;
pub mod validations;

use crate::domain::data_stores::UserStore;
use crate::routes::login::login_handler;
use crate::routes::logout::logout_handler;
use crate::routes::signup::signup_handler;
use crate::routes::verify_2fa::verify_2fa_handler;
use crate::routes::verify_token::verify_token_handler;
use axum::http::{Method, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::{env, fs};
use askama::Template;
use tokio::sync::RwLock;
use tower_http::cors::AllowOrigin;
use tower_http::{cors::CorsLayer, services::ServeDir};

// This struct encapsulates our application-related logic.
pub struct Application {
    address: SocketAddr,
    router: Router,
    tls_enabled: bool,
    listener: Option<tokio::net::TcpListener>,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {

        println!("Build with address: {:?}", address);

        let droplet_id = get_droplet_id();

        let allowed_origins = [
            "http://localhost:8000".parse()?,
            "https://localhost:8000".parse()?,
            format!("http://[{:?})]:8000", droplet_id).parse()?,
            format!("https://[{:?})]:8000", droplet_id).parse()?,
        ];

        let cors_layer = create_cors_layer(allowed_origins.into());

        let router = create_router(app_state, cors_layer);
        let addr: SocketAddr = address.parse()?;
        let tls_enabled = get_tls_config();

        // For tests and HTTP mode, pre-bind the listener to get the actual address
        let (actual_addr, listener) = if addr.port() == 0 || !tls_enabled {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let bound_addr = listener.local_addr()?;
            (bound_addr, Some(listener))
        } else {
            (addr, None)
        };

        Ok(Application {
            address: actual_addr,
            router,
            tls_enabled,
            listener,
        })
    }

    // Getter method for tests to access the bound address
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        if self.tls_enabled {
            println!("Starting auth-service with TLS on {}", self.address);
            self.start_https_server().await
        } else {
            println!("Starting auth-service with HTTP on {}", self.address);
            self.start_http_server().await
        }
    }

    async fn start_https_server(self) -> Result<(), Box<dyn Error>> {
        let cert_path = env::var("TLS_CERT_PATH").unwrap_or_else(|_| {
            "/etc/letsencrypt/live/bootcamp-auth.jocax.com/fullchain.pem".to_string()
        });
        let key_path = env::var("TLS_KEY_PATH").unwrap_or_else(|_| {
            "/etc/letsencrypt/live/bootcamp-auth.jocax.com/privkey.pem".to_string()
        });

        let config = RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .map_err(|e| format!("Failed to load TLS certificates: {}", e))?;

        axum_server::bind_rustls(self.address, config)
            .serve(self.router.into_make_service())
            .await
            .map_err(|e| e.into())
    }

    async fn start_http_server(self) -> Result<(), Box<dyn Error>> {
        let listener = match self.listener {
            Some(listener) => listener,
            None => tokio::net::TcpListener::bind(self.address).await?,
        };
        println!("listening on {}", listener.local_addr()?);
        axum::serve(listener, self.router)
            .await
            .map_err(|e| e.into())
    }
}

fn get_tls_config() -> bool {
    // In test mode, always disable TLS
    #[cfg(test)]
    return false;

    // In non-test mode, check environment
    #[cfg(not(test))]
    env::var("TLS_ENABLED")
        .unwrap_or_default()
        .parse::<bool>()
        .unwrap_or(false)
}

async fn root() -> impl IntoResponse {

let base_url = get_base_url();

    let template = IndexTemplate {
        base_url,
    };

    Html(template.render().unwrap())
}
async fn favicon() -> impl IntoResponse {
    let path = format!("{}/favicon.ico", get_assets_path().to_str().unwrap());

    match std::fs::read(path) {
        Ok(icon) => (
            [("Content-Type", "image/x-icon")],
            icon
        ).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn create_router(app_state: AppState, cors_layer: CorsLayer) -> Router {

    let assets_path = get_assets_path();

    let auth_router = Router::new()
        .nest_service("/assets", ServeDir::new(assets_path))
        .route("/", get(root))
        .route("/favicon.ico", get(favicon))
        .route("/api/signup", post(signup_handler))
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .route("/api/verify-2fa", post(verify_2fa_handler))
        .route("/api/verify-token", post(verify_token_handler))
        .with_state(app_state)
        .layer(cors_layer);

        auth_router

}

fn create_cors_layer(allowed_origins: AllowOrigin) -> CorsLayer {
    CorsLayer::new()
        // Allow GET and POST requests
        .allow_methods([Method::GET, Method::POST])
        // Allow cookies to be included in requests
        .allow_credentials(true)
        .allow_origin(allowed_origins)
}

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<dyn UserStore>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
}

impl AppState {
    pub fn new(user_store: UserStoreType) -> Self {
        Self { user_store }
    }
}

fn get_assets_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let assets_path = PathBuf::from(manifest_dir).join("assets");

    if !assets_path.exists() {
        panic!("Assets directory not found at {:?}", assets_path);
    }

    assets_path.to_path_buf()
}

fn get_droplet_id() -> String {
    env::var("DROPLET_ID").unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn get_base_url() -> String {
    env::var("BASE_URL").unwrap_or("http://localhost:8001".to_owned())
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    base_url: String,
}
