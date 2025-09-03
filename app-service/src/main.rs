use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use axum_extra::extract::CookieJar;
use axum_server::tls_rustls::RustlsConfig;
use serde::Serialize;
use std::env;
use std::net::SocketAddr;
use std::ops::Add;
use std::path::PathBuf;
use tower_http::services::ServeDir;

/// Must match with the port number used in docker-compose.yml for the app-service. Switched from 3000 -> 8001 due to local conflict
const AUTH_SERVICE_PORT: u16 = 8001u16;
const APP_SERVICE_PORT: u16 = 8000u16;

#[tokio::main]
async fn main() {
    let tls_enabled = get_tls_config();
    let addr = SocketAddr::from(([0, 0, 0, 0], APP_SERVICE_PORT));
    let app = create_router();

    if tls_enabled {
        println!("Starting app-service with TLS on {}", addr);
        start_https_server(app, addr).await;
    } else {
        println!("Starting app-service with HTTP on {}", addr);
        start_http_server(app, addr).await;
    }
}

async fn start_https_server(app: Router, addr: SocketAddr) {
    let cert_path = env::var("TLS_CERT_PATH").unwrap_or_else(|_| {
        "/etc/letsencrypt/live/bootcamp-app.jocax.com/fullchain.pem".to_string()
    });
    let key_path = env::var("TLS_KEY_PATH")
        .unwrap_or_else(|_| "/etc/letsencrypt/live/bootcamp-app.jocax.com/privkey.pem".to_string());

    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .expect("Failed to load TLS certificates");

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn start_http_server(app: Router, addr: SocketAddr) {
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

fn create_router() -> Router {
    let assets_path = get_assets_path();

    let app_router = Router::new()
        .nest_service("/assets", ServeDir::new(assets_path))
        .route("/", get(root))
        .route("/protected", get(protected))
        .route("/favicon.ico", get(favicon));

    app_router
}

async fn root() -> impl IntoResponse {
    let base_url = get_base_url();
    let login_link = get_auth_service_base_url();
    let logout_link = get_auth_service_base_url().add("/api/logout");

    let template = IndexTemplate {
        base_url,
        login_link,
        logout_link,
    };

    Html(template.render().unwrap())
}

async fn favicon() -> impl IntoResponse {
    let path = format!("{}/favicon.ico", get_assets_path().to_str().unwrap());

    match std::fs::read(path) {
        Ok(icon) => ([("Content-Type", "image/x-icon")], icon).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn protected(jar: CookieJar) -> impl IntoResponse {
    let jwt_cookie = match jar.get("jwt") {
        Some(cookie) => cookie,
        None => {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let api_client = reqwest::Client::builder().build().unwrap();

    let verify_token_body = serde_json::json!({
        "token": &jwt_cookie.value(),
    });

    let auth_hostname = env::var("AUTH_SERVICE_HOST_NAME").unwrap_or("localhost".to_owned());
    let tls_enabled = get_tls_config();
    let (protocol, port) = if tls_enabled {
        ("https", AUTH_SERVICE_PORT)
    } else {
        ("http", AUTH_SERVICE_PORT)
    };
    let url = format!(
        "{}://{}:{}/api/verify-token",
        protocol, auth_hostname, port
    );

    let response = match api_client.post(&url).json(&verify_token_body).send().await {
        Ok(response) => response,
        Err(_) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match response.status() {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::BAD_REQUEST => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        reqwest::StatusCode::OK => Json(ProtectedRouteResponse {
            img_url: "https://i.ibb.co/YP90j68/Light-Live-Bootcamp-Certificate.png".to_owned(),
        })
        .into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Serialize)]
pub struct ProtectedRouteResponse {
    pub img_url: String,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    base_url: String,
    login_link: String,
    logout_link: String,
}

fn get_base_url() -> String {
    env::var("BASE_URL").unwrap_or("http://localhost:8000".to_owned())
}
fn get_auth_service_base_url() -> String {
    env::var("AUTH_SERVICE_BASE_URL").unwrap_or("http://localhost:8001".to_owned())
}

fn get_assets_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let assets_path = PathBuf::from(manifest_dir).join("assets");

    if !assets_path.exists() {
        panic!("Assets directory not found at {:?}", assets_path);
    }

    assets_path.to_path_buf()
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
