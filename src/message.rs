use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedChatMessage {
    pub sender_id: String,
    pub payload: String,
    pub signature: String,
}

pub fn signing_payload(sender_id: &str, payload: &str) -> Vec<u8> {
    format!("{sender_id}\n{payload}").into_bytes()
}