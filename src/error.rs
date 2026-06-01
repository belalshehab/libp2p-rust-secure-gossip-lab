use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    InvalidKey(String),
    NodeNotFound(String),
    Libp2p(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "IO error: {e}"),
            AppError::Json(e) => write!(f, "JSON error: {e}"),
            AppError::Base64(e) => write!(f, "base64 error: {e}"),
            AppError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            AppError::NodeNotFound(id) => write!(f, "node not found: '{id}'"),
            AppError::Libp2p(msg) => write!(f, "libp2p error: {msg}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Json(e)
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(e: base64::DecodeError) -> Self {
        AppError::Base64(e)
    }
}

impl From<ed25519_dalek::SignatureError> for AppError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        AppError::InvalidKey(e.to_string())
    }
}
