pub mod validations;
pub mod api;
mod routes;
pub mod domain;
pub mod services;

use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use axum::Router;
use axum::response::Html;
use axum::routing::{get, post};
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use crate::domain::data_stores::UserStore;
use crate::routes::login::login_handler;
use crate::routes::logout::logout_handler;
use crate::routes::signup::signup_handler;
use crate::routes::verify_2fa::verify_2fa_handler;
use crate::routes::verify_token::verify_token_handler;

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

        let router = create_router(app_state);
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
        let cert_path = env::var("TLS_CERT_PATH")
            .unwrap_or_else(|_| "/etc/letsencrypt/live/bootcamp-auth.jocax.com/fullchain.pem".to_string());
        let key_path = env::var("TLS_KEY_PATH")
            .unwrap_or_else(|_| "/etc/letsencrypt/live/bootcamp-auth.jocax.com/privkey.pem".to_string());

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
        axum::serve(listener, self.router).await.map_err(|e| e.into())
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

async fn root_handler() -> Html<&'static str> {
    Html(include_str!("../assets/index.html"))
}

fn create_router(app_state: AppState) -> Router {

    let auth_router = Router::new()
        .route("/", get(root_handler))
        .nest_service("/assets", ServeDir::new("assets"))
        .route("/api/signup", post(signup_handler))
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .route("/api/verify-2fa", post(verify_2fa_handler))
        .route("/api/verify-token", post(verify_token_handler))
        .with_state(app_state);

    Router::new().nest("/auth", auth_router)
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
