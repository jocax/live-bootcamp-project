extern crate core;

mod routes;
pub mod model;

use std::error::Error;
use axum::Router;
use axum::routing::post;
use axum::serve::Serve;
use tower_http::services::ServeDir;
use crate::routes::{login_handler, logout_handler, signup_handler, verify_2fa_handler, verify_token_handler};

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<tokio::net::TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        println!("Build with address: {:?}", address);
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        let router  = Router::new()
            .fallback_service(ServeDir::new("assets"))
            .route("/api/signup", post(signup_handler))
            .route("/api/login", post(login_handler))
            .route("/api/logout", post(logout_handler))
            .route("/api/verify-2fa", post(verify_2fa_handler))
            .route("/api/verify-token", post(verify_token_handler))
            ;


        let listener = tokio::net::TcpListener::bind(address).await?;
        let listener_address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        Ok(Application {
            server,
            address: listener_address,
        })
    }
    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
