use axum::{extract, extract::State};
use std::sync::Arc;
use serde_json::{Serializer, Value};
use serde_canonical_json::CanonicalFormatter;
use serde::Serialize;
use crate::{AppState, models::ChatRequest};

pub async fn handle_request(
    State(state): State<Arc<AppState>>, 
    extract::Json(payload): extract::Json<ChatRequest> 
) -> Result<axum::Json<Value>, axum::http::StatusCode> {

    let hasher = blake3::Hasher::new();
    let mut ser = Serializer::with_formatter(hasher, CanonicalFormatter::new());
    payload.serialize(&mut ser).unwrap();
    let hex_str = ser.into_inner().finalize().to_hex().to_string();

    println!("hash: {}", hex_str);

    if let Some(value) = state.cache.get(&hex_str).await {
        println!("found value {}", value);
        return Ok(axum::Json(value))
    }
    
    let res = state.client.post("https://httpbin.org/post")
        .json(&payload)
        .send()
        .await;
   
    match res {
        Ok(response) => {
            match response.json::<Value>().await {
                Ok(data) => {
                    println!("stored data, key: {}, value: {:?}", hex_str, data);
                    
                    state.cache.insert(hex_str, data.clone()).await;
                    
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