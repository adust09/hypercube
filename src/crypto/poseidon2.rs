use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::crypto::hash::HashFunction;

type F = GoldilocksField;
type Hash = PoseidonHash;

/// Poseidon2 hash function implementation for ZK-friendly hashing
pub struct Poseidon2Hash {
    /// Internal hasher instance
    hasher: Hash,
}

impl Poseidon2Hash {
    pub fn new() -> Self {
        Self {
            hasher: PoseidonHash,
        }
    }

    /// Hash field elements directly (for ZK circuit use)
    pub fn hash_elements<F: RichField>(&self, elements: &[F]) -> HashOut<F> {
        PoseidonHash::hash_no_pad(elements)
    }

    /// Hash field elements with padding
    pub fn hash_elements_padded<F: RichField>(&self, elements: &[F]) -> HashOut<F> {
        PoseidonHash::hash_pad(elements)
    }

    /// Convert bytes to field elements for hashing
    fn bytes_to_field_elements(bytes: &[u8]) -> Vec<F> {
        let mut elements = Vec::new();
        
        // Pack bytes into field elements (8 bytes per element for Goldilocks)
        for chunk in bytes.chunks(8) {
            let mut value = 0u64;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u64) << (i * 8);
            }
            elements.push(F::from_canonical_u64(value));
        }
        
        elements
    }

    /// Convert field elements back to bytes
    fn field_elements_to_bytes(elements: &[F]) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        for &element in elements {
            let value = element.to_noncanonical_u64();
            for i in 0..8 {
                bytes.push(((value >> (i * 8)) & 0xFF) as u8);
            }
        }
        
        bytes
    }
}

impl HashFunction for Poseidon2Hash {
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        // Convert input bytes to field elements
        let elements = Self::bytes_to_field_elements(input);
        
        // Hash the elements
        let hash_out = self.hash_elements_padded(&elements);
        
        // Convert hash output back to bytes
        let mut result = Vec::new();
        for &element in hash_out.elements.iter() {
            let bytes = element.to_noncanonical_u64().to_le_bytes();
            result.extend_from_slice(&bytes);
        }
        
        result
    }

    fn output_size(&self) -> usize {
        // Poseidon hash outputs 4 field elements in Goldilocks
        // Each element is 8 bytes
        32
    }
}

impl Default for Poseidon2Hash {
    fn default() -> Self {
        Self::new()
    }
}

/// Poseidon2 hash chain implementation for WOTS
pub fn poseidon2_hash_chain(input: &[u8], iterations: usize) -> Vec<u8> {
    let hasher = Poseidon2Hash::new();
    let mut result = input.to_vec();
    
    for _ in 0..iterations {
        result = hasher.hash(&result);
    }
    
    result
}

/// Poseidon2 hash chain for field elements (more efficient for circuits)
pub fn poseidon2_hash_chain_elements<F: RichField>(
    input: HashOut<F>,
    iterations: usize,
) -> HashOut<F> {
    let mut result = input;
    
    for _ in 0..iterations {
        result = PoseidonHash::hash_no_pad(&result.elements);
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon2_hash_basic() {
        let hasher = Poseidon2Hash::new();
        let input = b"Hello, Poseidon2!";
        let hash = hasher.hash(input);
        
        assert_eq!(hash.len(), hasher.output_size());
    }

    #[test]
    fn test_poseidon2_hash_empty() {
        let hasher = Poseidon2Hash::new();
        let input = b"";
        let hash = hasher.hash(input);
        
        assert_eq!(hash.len(), hasher.output_size());
    }

    #[test]
    fn test_poseidon2_hash_chain() {
        let input = b"test input";
        let result1 = poseidon2_hash_chain(input, 1);
        let result2 = poseidon2_hash_chain(input, 2);
        let result3 = poseidon2_hash_chain(input, 3);
        
        // Each iteration should produce different results
        assert_ne!(result1, result2);
        assert_ne!(result2, result3);
        assert_ne!(result1, result3);
        
        // Verify chain property: hash(hash(x)) = hash_chain(x, 2)
        let hasher = Poseidon2Hash::new();
        let manual_chain = hasher.hash(&hasher.hash(input));
        assert_eq!(manual_chain, result2);
    }

    #[test]
    fn test_field_element_conversion() {
        let input = b"Test data for field element conversion";
        let elements = Poseidon2Hash::bytes_to_field_elements(input);
        let reconstructed = Poseidon2Hash::field_elements_to_bytes(&elements);
        
        // Should be able to reconstruct the original input (padded to 8-byte chunks)
        assert_eq!(&reconstructed[..input.len()], input);
    }
}