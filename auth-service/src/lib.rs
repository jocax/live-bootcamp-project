mod routes;

use std::error::Error;
use axum::Router;
use axum::routing::get;
use axum::serve::Serve;
use tower_http::services::ServeDir;
use crate::routes::hello_handler;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
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
            .nest_service("/", ServeDir::new("assets"));
            //.route("/hello", get(hello_handler));

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
