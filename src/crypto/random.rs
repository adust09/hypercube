// Random number generation

use rand::rngs::OsRng;
use rand::RngCore;

/// Secure random number generator trait
pub trait SecureRandom {
    /// Generate random bytes
    fn random_bytes(&mut self, size: usize,) -> Vec<u8,>;
}

/// OS-based secure random number generator
pub struct OsSecureRandom {
    rng: OsRng,
}

impl OsSecureRandom {
    pub fn new() -> Self {
        OsSecureRandom { rng: OsRng, }
    }
}

impl SecureRandom for OsSecureRandom {
    fn random_bytes(&mut self, size: usize,) -> Vec<u8,> {
        let mut bytes = vec![0u8; size];
        self.rng.fill_bytes(&mut bytes,);
        bytes
    }
}

/// Deterministic RNG for testing
pub struct DeterministicRng {
    seed: Vec<u8,>,
    counter: usize,
}

impl DeterministicRng {
    pub fn new(seed: &[u8],) -> Self {
        DeterministicRng { seed: seed.to_vec(), counter: 0, }
    }
}

impl SecureRandom for DeterministicRng {
    fn random_bytes(&mut self, size: usize,) -> Vec<u8,> {
        // Simple deterministic generation for testing
        use crate::crypto::hash::{HashFunction, SHA256};
        let hasher = SHA256::new();

        let mut result = Vec::with_capacity(size,);
        while result.len() < size {
            let mut input = self.seed.clone();
            input.extend_from_slice(&self.counter.to_le_bytes(),);
            self.counter += 1;

            let hash = hasher.hash(&input,);
            result.extend_from_slice(&hash,);
        }
        result.truncate(size,);
        result
    }
}
