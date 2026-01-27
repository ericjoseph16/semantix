use axum::{
    extract,
    extract::State,
    routing::{post},
    Router,
};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use serde_json::{Serializer, Value};
use serde_canonical_json::CanonicalFormatter;

#[derive(Deserialize, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Deserialize, Serialize)]
struct Message {
    role: String,
    content: String,
}

struct AppState {
    client: reqwest::Client,
}

async fn handle_request(
    State(state): State<Arc<AppState>>, 
    extract::Json(payload): extract::Json<ChatRequest> 
) -> Result<axum::Json<Value>, axum::http::StatusCode> {
    
    let res = state.client.post("https://httpbin.org/post")
        .json(&payload)
        .send()
        .await;
   
    match res {
        Ok(response) => {
            match response.json::<Value>().await {
                Ok(data) => {
                    let hasher = blake3::Hasher::new();
                    let mut ser = Serializer::with_formatter(hasher, CanonicalFormatter::new());
                    data.serialize(&mut ser).unwrap();
                    let recovered_hasher = ser.into_inner();
                    let hash_res = recovered_hasher.finalize();
                    let hex_str = hash_res.to_hex().to_string();
                    
                    println!("SUCCESS! Hash: {}", hex_str);
                    Ok(axum::Json(data))
                }
                Err(e) => {
                    println!("JSON Error: {}", e);
                    Err(axum::http::StatusCode::BAD_GATEWAY)
                }
            }
        }
        Err(e) => {
            println!("Request Error: {}", e);
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[tokio::main]
async fn main() {

    let shared_state = Arc::new(AppState {
        client: reqwest::Client::new(),
    });

    // let app = Router::new().route("/", get(|| async{ "Hello World!" }));
    let app = Router::new().route("/", post(handle_request)).with_state(shared_state);
    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Proxy is running on http://{}", addr);
    
    axum::serve(listener, app).await.unwrap();

}