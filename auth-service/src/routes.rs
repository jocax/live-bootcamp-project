use axum::response::Html;

pub async fn hello_handler() -> Html<&'static str> {
    Html("<h1>Welcome to Sprint 1</h1>")
}