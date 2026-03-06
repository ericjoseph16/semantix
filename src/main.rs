mod models;
mod cache;
mod handlers;

use axum::{routing::post, Router};
use std::sync::Arc;
use crate::cache::Cache;

pub struct AppState {
    pub client: reqwest::Client,
    pub cache: Cache,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shared_state = Arc::new(AppState {
        client: reqwest::Client::new(),
        cache: Cache::new(),
    });

    let app = Router::new()
        .route("/", post(handlers::handle_request))
        .with_state(shared_state);

    let addr = "127.0.0.1:3001";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Proxy is running on http://{}", addr);
    
    axum::serve(listener, app).await.unwrap();
    Ok(())
}