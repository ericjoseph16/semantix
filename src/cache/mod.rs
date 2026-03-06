// persistence layer (sqlite sqlx database)

use serde_json::Value;

pub struct Cache {
    // Preparing to swap this for an sqlx::SqlitePool
}

impl Cache {
    pub fn new() -> Self {
        // Just return an empty struct for now
        Self {}
    }

    pub async fn get(&self, _key: &str) -> Option<Value> {
        // Placeholder: Will be 'db.get(key)' later
        None
    }

    pub async fn insert(&self, _key: String, _value: Value) {
        // Placeholder: Will be 'db.insert(key, value)' later
    }
}