mod key_pair;
mod service;

use crate::service::DocSigner;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{error::Error, time::SystemTime};

#[derive(Debug)]
struct CustomError(String);

impl std::fmt::Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for CustomError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DocumentMetadata {
    content_type: String,
    hash_algorithm: String,
    signature_algorithm: String,
    expiration: SystemTime,
}

struct InputDocument {
    id: String,
    content: Vec<u8>,
}

// Core data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedDocument {
    document_id: String,
    content: Vec<u8>,
    signature: Vec<u8>,
    timestamp: SystemTime,
    signer_id: String,
    metadata: DocumentMetadata,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 30 days
    let expires_at = Duration::from_secs(30 * 24 * 60 * 60);
    let mut signer = DocSigner::new("demo_signer", expires_at);

    let input_doc = InputDocument {
        id: "doc123".to_string(),
        content: Vec::from(b"Hello, Digital Signatures!"),
    };

    let signed_doc = signer.sign(input_doc).await?;
    println!("Signature for document ID: {:#?}", signed_doc);

    let verified = signer.verify(signed_doc).await?;
    if verified {
        println!("✅ Signature verified.");
    } else {
        println!("❌ Signature verification failed.");
    }

    Ok(())
}
