use crate::key_pair::Ed25519KeyPairGenerator;
use crate::{DocumentMetadata, InputDocument, SignedDocument};
use ring::signature;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;
use std::error::Error;
use std::time::{Duration, SystemTime};

pub struct DocSigner {
    signer_id: String,
    expires_at: Duration,
    keypair: HashMap<String, Ed25519KeyPair>,
}

impl DocSigner {
    pub(crate) fn new(signer_id: &str, expires_at: Duration) -> Self {
        Self {
            signer_id: signer_id.to_string(),
            expires_at,
            keypair: HashMap::new(),
        }
    }

    pub(crate) async fn sign(
        &mut self,
        input_doc: InputDocument,
    ) -> Result<SignedDocument, Box<dyn Error>> {
        let key_pair = Ed25519KeyPairGenerator::generate()?.key_pair;
        let signature = key_pair.sign(&input_doc.content);
        self.keypair.insert(self.signer_id.to_string(), key_pair);

        let signed_doc = SignedDocument {
            document_id: input_doc.id,
            content: input_doc.content,
            signature: signature.as_ref().to_vec(),
            timestamp: SystemTime::now(),
            signer_id: self.signer_id.to_string(),
            metadata: DocumentMetadata {
                content_type: "application/octet-stream".to_string(),
                hash_algorithm: "SHA256".to_string(),
                signature_algorithm: "Ed25519".to_string(),
                expiration: SystemTime::now() + self.expires_at,
            },
        };

        Ok(signed_doc)
    }

    pub(crate) async fn verify(&self, signed_doc: SignedDocument) -> Result<bool, Box<dyn Error>> {
        if SystemTime::now() > signed_doc.metadata.expiration {
            return Err("Document signature has expired".into());
        }

        let key_pair = self
            .keypair
            .get(&self.signer_id.to_string())
            .expect("Key pair not found");
        
        let public_key = key_pair.public_key();
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, public_key.as_ref());

        match peer_public_key.verify(&signed_doc.content, &signed_doc.signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
