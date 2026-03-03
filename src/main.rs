use axum::{
    extract,
    extract::State,
    routing::{post},
    Router,
};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::collections::HashMap;
use std::io::BufReader;
use std::fs::File;
use std::path::Path;
use std::time::SystemTime;
use serde_json::{Serializer, Value};
use serde_canonical_json::CanonicalFormatter;
use dashmap::DashMap;
use tokio::io::AsyncWriteExt;

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
    cache: DashMap<String, Value>,
}

async fn save_to_disk(
    State(state): State<Arc<AppState>>
) {
    let mut cache_hashmap: HashMap<String, Value> = HashMap::new();

    for entry in state.cache.iter() {
        cache_hashmap.insert(entry.key().clone(), entry.value().clone());
    }
    // serialize to json string

    let serialized = serde_json::to_string(&cache_hashmap).expect("Failed to serialize");

    // save to temp then rename - use tokio spawn for async

    tokio::spawn(save_temp_rename(serialized));

}

async fn save_temp_rename(data: String) -> Result<(), std::io::Error> {
    let sys_time = SystemTime::now();
    let temp_path = format!("cache/cache.json{:?}.tmp", sys_time.duration_since(UNIX_EPOCH).unwrap().as_nanos());
    let mut temp_file = tokio::fs::File::create(temp_path).await?;
    temp_file.write_all(data.as_bytes()).await?;

    tokio::fs::rename("temp.txt", "perm.txt").await?;
    
    Ok(())
}

async fn handle_request(
    State(state): State<Arc<AppState>>, 
    extract::Json(payload): extract::Json<ChatRequest> 
) -> Result<axum::Json<Value>, axum::http::StatusCode> {

    let hasher = blake3::Hasher::new();
    let mut ser = Serializer::with_formatter(hasher, CanonicalFormatter::new());
    payload.serialize(&mut ser).unwrap();
    let recovered_hasher = ser.into_inner();
    let hash_res = recovered_hasher.finalize();
    let hex_str = hash_res.to_hex().to_string();

    println!("hash: {}", hex_str);

    if let Some(value) = state.cache.get(&hex_str) {
        println!("found value {}", *value);
        // clone to return data to user (only clones data not the guard)
        return Ok(axum::Json(value.clone()))
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
                    state.cache.insert(hex_str, data.clone());
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

pub fn hydrate_cache(path: &str) -> Result<DashMap<String, Value>, Box<dyn std::error::Error>>{
    if !Path::new(path).exists() {
        return Ok(DashMap::new());
    }

    // read data
    let file = File::open(path)?;
    let buf_reader = BufReader::new(file);
    // parse data, direct deserialization from file stream into HashMap (cannot directly deserialize to DashMap)
    let map: HashMap<String, Value> = serde_json::from_reader(buf_reader)?;

    // populate dashmap with map values
    let dashmap = DashMap::new();
    for (key, value) in map {
        dashmap.insert(key, value);
    }

    Ok(dashmap)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    // create dir, ignored if dir already exists
    std::fs::create_dir_all("cache/")?;

    let path = "cache/cache.json";
    let cache = hydrate_cache(path).expect("Failed to hydrate cache");

    let shared_state = Arc::new(AppState {
        client: reqwest::Client::new(),
        cache,
    });

    // let app = Router::new().route("/", get(|| async{ "Hello World!" }));
    let app = Router::new().route("/", post(handle_request)).with_state(shared_state);
    let addr = "127.0.0.1:3001";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Proxy is running on http://{}", addr);
    
    axum::serve(listener, app).await.unwrap();
    Ok(())

}