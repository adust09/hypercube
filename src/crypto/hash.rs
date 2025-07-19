// Hash function abstractions

use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// Trait for hash functions
pub trait HashFunction {
    /// Hash input data
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// Get output size in bytes
    fn output_size(&self) -> usize;
}

/// SHA-256 hash function
pub struct SHA256;

impl SHA256 {
    pub fn new() -> Self {
        SHA256
    }
}

impl HashFunction for SHA256 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }
}

/// SHA3-256 hash function
pub struct SHA3_256;

impl SHA3_256 {
    pub fn new() -> Self {
        SHA3_256
    }
}

impl HashFunction for SHA3_256 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }
}
