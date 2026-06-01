use std::collections::HashMap;
use std::fmt;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Debug, Eq, PartialEq)]
pub enum VerifyingError {
    EmptyPayload,
    UnknownSender,
    InvalidSignature,
    MalformedSignature,
}

impl fmt::Display for VerifyingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyingError::EmptyPayload => write!(f, "empty payload"),
            VerifyingError::UnknownSender => write!(f, "unknown sender"),
            VerifyingError::MalformedSignature => write!(f, "malformed signature"),
            VerifyingError::InvalidSignature => write!(f, "invalid signature"),
        }
    }
}
#[derive(Default)]
pub struct Validator {
    trusted_peers: HashMap<String, VerifyingKey>,
}

impl Validator {
    pub fn add_trusted_peer(&mut self, peer_id: &str, verifying_key: VerifyingKey) {
        self.trusted_peers
            .insert(peer_id.to_string(), verifying_key);
    }

    pub fn validate_signature(
        &self,
        peer_id: &str,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), VerifyingError> {
        if payload.is_empty() {
            return Err(VerifyingError::EmptyPayload);
        }
        let verifying_key = self
            .trusted_peers
            .get(peer_id)
            .ok_or(VerifyingError::UnknownSender)?;

        let signature =
            Signature::from_slice(signature).map_err(|_| VerifyingError::MalformedSignature)?;

        verifying_key
            .verify(payload, &signature)
            .map_err(|_| VerifyingError::InvalidSignature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn setup_trusted_peers() -> (HashMap<String, SigningKey>, Validator) {
        let mut private_keys = HashMap::new();

        let mut validator = Validator::default();
        let (signing_key, verifying_key) = generate_keypair();
        private_keys.insert("Alice".to_string(), signing_key);
        validator.add_trusted_peer("Alice", verifying_key);

        let (signing_key, verifying_key) = generate_keypair();
        private_keys.insert("Bob".to_string(), signing_key);
        validator.add_trusted_peer("Bob", verifying_key);

        let (signing_key, _) = generate_keypair();
        private_keys.insert("Mallory".to_string(), signing_key);

        (private_keys, validator)
    }

    #[test]
    fn valid_signature() {
        let (private_keys, validator) = setup_trusted_peers();
        let payload = "payload";
        let signing_key = &private_keys["Alice"];
        let signature = signing_key.sign(payload.as_bytes());

        assert!(
            validator
                .validate_signature("Alice", payload.as_bytes(), &signature.to_bytes())
                .is_ok()
        );
    }

    #[test]
    fn tampered_payload() {
        let (private_keys, validator) = setup_trusted_peers();
        let payload = "payload";
        let signing_key = &private_keys["Alice"];
        let signature = signing_key.sign(payload.as_bytes());

        let payload = "hacked";
        assert_eq!(
            validator.validate_signature("Alice", payload.as_bytes(), &signature.to_bytes()),
            Err(VerifyingError::InvalidSignature)
        );
    }

    #[test]
    fn signature_from_wrong_peer_is_rejected() {
        let (private_keys, validator) = setup_trusted_peers();
        let payload = "payload";
        let signing_key = &private_keys["Bob"];
        let signature = signing_key.sign(payload.as_bytes());

        assert_eq!(
            validator.validate_signature("Alice", payload.as_bytes(), &signature.to_bytes()),
            Err(VerifyingError::InvalidSignature)
        );
    }

    #[test]
    fn empty_payload() {
        let (private_keys, validator) = setup_trusted_peers();
        let signing_key = &private_keys["Alice"];
        let signature = signing_key.sign("".as_bytes());

        assert_eq!(
            validator.validate_signature("Alice", "".as_bytes(), &signature.to_bytes()),
            Err(VerifyingError::EmptyPayload)
        );
    }

    #[test]
    fn unknown_peer() {
        let (_, validator) = setup_trusted_peers();
        let payload = "payload";
        let signature = [1, 2, 3];

        assert_eq!(
            validator.validate_signature("Mallory", payload.as_bytes(), &signature),
            Err(VerifyingError::UnknownSender)
        );
    }

    #[test]
    fn malformed_signature() {
        let (private_keys, validator) = setup_trusted_peers();
        let payload = "payload";
        let signing_key = &private_keys["Alice"];
        let signature = signing_key.sign(payload.as_bytes());

        assert_eq!(
            validator.validate_signature("Alice", payload.as_bytes(), &signature.to_bytes()[1..]),
            Err(VerifyingError::MalformedSignature)
        );
    }
}
