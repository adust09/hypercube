use crate::aggregate::{AggregateError, AggregateProof, F, PublicInputs};
use crate::wots::WotsPublicKey;

/// Verifies aggregate proofs
pub struct AggregateVerifier;

impl AggregateVerifier {
    /// Verify an aggregate proof
    pub fn verify(
        proof: &AggregateProof,
        message: &[u8],
        public_keys: &[WotsPublicKey],
    ) -> Result<bool, AggregateError> {
        // Check that the number of public keys matches
        if public_keys.len() != proof.num_signatures {
            return Err(AggregateError::MismatchedCount);
        }
        
        // Reconstruct the expected public inputs
        let expected_public_inputs = Self::reconstruct_public_inputs(message, public_keys)?;
        
        // Extract the actual public inputs from the proof
        let actual_public_inputs = &proof.proof.public_inputs;
        
        // Verify they match
        if actual_public_inputs.len() != expected_public_inputs.len() {
            return Err(AggregateError::InvalidPublicInputs);
        }
        
        for (actual, expected) in actual_public_inputs.iter()
            .zip(expected_public_inputs.iter())
        {
            if actual != expected {
                return Err(AggregateError::InvalidPublicInputs);
            }
        }
        
        // Verify the proof itself
        proof.circuit_data.verify(proof.proof.clone())
            .map_err(|_| AggregateError::VerificationFailed)?;
        
        Ok(true)
    }
    
    /// Reconstruct the expected public inputs
    fn reconstruct_public_inputs(
        message: &[u8],
        public_keys: &[WotsPublicKey],
    ) -> Result<Vec<F>, AggregateError> {
        use plonky2::field::types::Field;
        use plonky2::hash::poseidon::PoseidonHash;
        use plonky2::plonk::config::Hasher;
        
        let mut inputs = Vec::new();
        
        // Hash the message
        let message_hash = crate::aggregate::aggregator::Aggregator::hash_message(message);
        inputs.extend(&message_hash.elements);
        
        // Add public key commitments
        for pk in public_keys {
            let mut elements = Vec::new();
            for chain in pk.chains() {
                for chunk in chain.chunks(8) {
                    let mut value = 0u64;
                    for (i, &byte) in chunk.iter().enumerate() {
                        value |= (byte as u64) << (i * 8);
                    }
                    elements.push(F::from_canonical_u64(value));
                }
            }
            let hash = PoseidonHash::hash_no_pad(&elements);
            inputs.extend(&hash.elements);
        }
        
        Ok(inputs)
    }
    
    /// Verify with explicit public inputs (for testing)
    pub fn verify_with_public_inputs(
        proof: &AggregateProof,
        public_inputs: &PublicInputs,
    ) -> Result<bool, AggregateError> {
        // Convert public inputs to field elements
        let expected_elements = public_inputs.to_field_elements();
        let actual_elements = &proof.proof.public_inputs;
        
        // Check they match
        if expected_elements.len() != actual_elements.len() {
            return Err(AggregateError::InvalidPublicInputs);
        }
        
        for (expected, actual) in expected_elements.iter().zip(actual_elements.iter()) {
            if expected != actual {
                return Err(AggregateError::InvalidPublicInputs);
            }
        }
        
        // Verify the proof
        proof.circuit_data.verify(proof.proof.clone())
            .map_err(|_| AggregateError::VerificationFailed)?;
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    
    #[test]
    fn test_verifier_basic() {
        // Basic test to ensure the verifier compiles
        let _verifier = super::AggregateVerifier;
        assert!(true);
    }
}