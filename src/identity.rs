use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Serialize, Deserialize)]
pub struct NodeEntry {
    pub public_key: String,  // base64-encoded 32 bytes
    pub private_key: String, // base64-encoded 32 bytes
}
#[derive(Serialize, Deserialize)]
pub struct KeysFile {
    pub nodes: HashMap<String, NodeEntry>,
    pub trusted_senders: HashMap<String, String>, // node_id -> base64 public key
}

pub struct NodeIdentity {
    pub node_id: String,
    pub signing_key: SigningKey,
}

pub fn load_keys_file(path: &str) -> Result<KeysFile, AppError> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn load_node_identity(keys: &KeysFile, node_id: &str) -> Result<NodeIdentity, AppError> {
    let entry = keys
        .nodes
        .get(node_id)
        .ok_or_else(|| AppError::NodeNotFound(node_id.to_string()))?;
    let bytes = STANDARD.decode(&entry.private_key)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::InvalidKey("private key must be 32 bytes".to_string()))?;
    Ok(NodeIdentity {
        node_id: node_id.to_string(),
        signing_key: SigningKey::from_bytes(&arr),
    })
}

pub fn load_trusted_keys(keys: &KeysFile) -> Result<HashMap<String, VerifyingKey>, AppError> {
    let mut map = HashMap::new();
    for (id, b64) in &keys.trusted_senders {
        let bytes = STANDARD.decode(b64)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AppError::InvalidKey("public key must be 32 bytes".to_string()))?;
        map.insert(id.clone(), VerifyingKey::from_bytes(&arr)?);
    }
    Ok(map)
}

pub fn generate_demo_keys_file(path: &str) -> Result<(), AppError> {
    let node_ids = ["node1", "node2", "node3"];
    let mut nodes = HashMap::new();
    let mut trusted_senders = HashMap::new();

    for id in node_ids {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        nodes.insert(
            id.to_string(),
            NodeEntry {
                private_key: STANDARD.encode(signing_key.to_bytes()),
                public_key: STANDARD.encode(verifying_key.to_bytes()),
            },
        );
        trusted_senders.insert(id.to_string(), STANDARD.encode(verifying_key.to_bytes()));
    }

    let keys_file = KeysFile {
        nodes,
        trusted_senders,
    };
    std::fs::create_dir_all("keys")?;
    std::fs::write(path, serde_json::to_string_pretty(&keys_file)?)?;
    println!("Generated keys at {path}");
    Ok(())
}
