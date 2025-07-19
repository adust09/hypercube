use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::aggregate::{AggregateError, F, SignatureBundle};
use crate::wots::{WotsPublicKey, WotsSignature};

/// Manages a set of signatures for aggregation
pub struct SignatureSet {
    signatures: Vec<WotsSignature>,
    public_keys: Vec<WotsPublicKey>,
    message: Vec<u8>,
}

impl SignatureSet {
    /// Create a new signature set
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            public_keys: Vec::new(),
            message: Vec::new(),
        }
    }
    
    /// Set the message for this signature set
    pub fn set_message(&mut self, message: Vec<u8>) {
        self.message = message;
    }
    
    /// Add a signature and corresponding public key
    pub fn add_signature(
        &mut self,
        signature: WotsSignature,
        public_key: WotsPublicKey,
    ) -> Result<(), AggregateError> {
        // Basic validation
        if signature.chains().len() != public_key.chains().len() {
            return Err(AggregateError::InvalidSignature(self.signatures.len()));
        }
        
        self.signatures.push(signature);
        self.public_keys.push(public_key);
        Ok(())
    }
    
    /// Convert to SignatureBundle for processing
    pub fn to_bundle(self) -> Result<SignatureBundle, AggregateError> {
        SignatureBundle::new(self.signatures, self.public_keys, self.message)
    }
    
    /// Get the number of signatures in the set
    pub fn len(&self) -> usize {
        self.signatures.len()
    }
    
    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
    
    /// Compute a commitment to all public keys
    pub fn compute_public_key_commitment(&self) -> Vec<HashOut<F>> {
        self.public_keys
            .iter()
            .map(|pk| {
                // Hash all chains of the public key together
                let mut elements = Vec::new();
                for chain in pk.chains() {
                    // Convert bytes to field elements
                    for chunk in chain.chunks(8) {
                        let mut value = 0u64;
                        for (i, &byte) in chunk.iter().enumerate() {
                            value |= (byte as u64) << (i * 8);
                        }
                        elements.push(F::from_canonical_u64(value));
                    }
                }
                PoseidonHash::hash_no_pad(&elements)
            })
            .collect()
    }
    
    /// Verify all signatures in the set (for testing)
    pub fn verify_all(&self) -> Result<bool, AggregateError> {
        if self.signatures.len() != self.public_keys.len() {
            return Err(AggregateError::MismatchedCount);
        }
        
        // This would use the encoding scheme to verify each signature
        // For now, we'll return true as a placeholder
        // In a real implementation, we'd need the encoding scheme
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wots::{WotsParams, WotsKeypair};
    
    #[test]
    fn test_signature_set_basic() {
        let mut set = SignatureSet::new();
        assert!(set.is_empty());
        
        set.set_message(b"test message".to_vec());
        assert_eq!(set.len(), 0);
    }
    
    #[test]
    fn test_signature_set_add() {
        let mut set = SignatureSet::new();
        set.set_message(b"test message".to_vec());
        
        // Create a dummy WOTS keypair
        let params = WotsParams::new(16, 32);
        let keypair = WotsKeypair::generate(&params);
        
        // Create a dummy signature (normally would sign the message)
        let message_digest = vec![5; 32]; // Dummy digest
        let signature = keypair.sign(&message_digest);
        
        // Add to set
        let result = set.add_signature(signature, keypair.public_key().clone());
        assert!(result.is_ok());
        assert_eq!(set.len(), 1);
    }
}