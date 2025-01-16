use crate::CustomError;
use ring::rand;
use ring::signature::Ed25519KeyPair;
use std::error::Error;

#[derive(Debug)]
pub struct Ed25519KeyPairGenerator {
    pub(crate) key_pair: Ed25519KeyPair,
}

impl Ed25519KeyPairGenerator {
    pub fn generate() -> Result<Ed25519KeyPairGenerator, Box<dyn Error>> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| {
            Box::new(CustomError(format!("Failed to generate PKCS8: {:?}", e))) as Box<dyn Error>
        })?;

        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).map_err(|e| {
            Box::new(CustomError(format!("Failed to create key pair: {:?}", e))) as Box<dyn Error>
        })?;

        let key_wrapper = Ed25519KeyPairGenerator {
            key_pair
        };

        Ok(key_wrapper)
    }
}


#[cfg(test)]
mod tests {
    use crate::key_pair::Ed25519KeyPairGenerator;
    use ring::signature::KeyPair;

    #[test]
    fn test_keypair_operations() {
        let key_pair = Ed25519KeyPairGenerator::generate().unwrap();
        assert_eq!(key_pair.key_pair.public_key().as_ref().len(), 32);
    }
}