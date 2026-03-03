// data layer (structs)

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