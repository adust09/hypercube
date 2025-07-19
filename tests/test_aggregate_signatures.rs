use hypercube_signatures::aggregate::SignatureBundle;
use hypercube_signatures::aggregate::signature_set::SignatureSet;
use hypercube_signatures::aggregate::aggregator::Aggregator;
use hypercube_signatures::crypto::poseidon2::Poseidon2Hash;
use hypercube_signatures::crypto::hash::HashFunction;
use hypercube_signatures::schemes::tsl::{TSL, TSLConfig};
use hypercube_signatures::wots::{WotsParams, WotsKeypair};
use hypercube_signatures::wots_poseidon::WotsPoseidon2Params;
use hypercube_signatures::wots_poseidon::keypair::WotsPoseidon2Keypair;

#[test]
fn test_poseidon2_hash_consistency() {
    let hasher = Poseidon2Hash::new();
    let input = b"test message for hashing";
    
    // Hash the same input multiple times
    let hash1 = hasher.hash(input);
    let hash2 = hasher.hash(input);
    
    assert_eq!(hash1, hash2, "Poseidon2 hash should be deterministic");
    assert_eq!(hash1.len(), hasher.output_size(), "Hash output size mismatch");
}

#[test]
fn test_signature_set_creation() {
    let mut set = SignatureSet::new();
    set.set_message(b"test message".to_vec());
    
    // Create dummy WOTS keypairs and signatures
    let params = WotsParams::new(16, 32);
    
    for i in 0..3 {
        let keypair = WotsKeypair::generate(&params);
        let message_digest: Vec<usize> = (1..=32).map(|j| ((j + i) % 15) + 1).collect();
        let signature = keypair.sign(&message_digest);
        
        let result = set.add_signature(signature, keypair.public_key().clone());
        assert!(result.is_ok(), "Failed to add signature {}", i);
    }
    
    assert_eq!(set.len(), 3, "SignatureSet should contain 3 signatures");
}

#[test]
fn test_poseidon2_wots_sign_verify() {
    let params = WotsPoseidon2Params::new(16, 32);
    let keypair = WotsPoseidon2Keypair::generate(&params);
    
    // Create a message digest
    let message_digest: Vec<usize> = (1..=32).map(|i| (i % 15) + 1).collect();
    
    // Sign the message
    let signature = keypair.sign(&message_digest);
    
    // Verify the signature
    assert!(
        keypair.verify(&message_digest, &signature),
        "Valid signature should verify"
    );
    
    // Verify with wrong message fails
    let wrong_digest: Vec<usize> = (1..=32).map(|i| ((i + 5) % 15) + 1).collect();
    assert!(
        !keypair.verify(&wrong_digest, &signature),
        "Invalid signature should not verify"
    );
}

#[test]
fn test_aggregate_proof_creation() {
    // Create a signature bundle
    let params = WotsParams::new(16, 32);
    let message = b"test message for aggregation";
    
    let mut signatures = Vec::new();
    let mut public_keys = Vec::new();
    
    // Generate 3 signatures
    for _ in 0..3 {
        let keypair = WotsKeypair::generate(&params);
        let message_digest: Vec<usize> = (1..=32).map(|i| (i % 15) + 1).collect();
        let signature = keypair.sign(&message_digest);
        
        signatures.push(signature);
        public_keys.push(keypair.public_key().clone());
    }
    
    let bundle = SignatureBundle::new(signatures, public_keys, message.to_vec())
        .expect("Failed to create signature bundle");
    
    // Create TSL scheme for encoding
    // Use default parameters for 128-bit security
    let tsl_config = TSLConfig::new(128);
    let tsl = TSL::new(tsl_config);
    
    // Create aggregator and generate proof
    let aggregator = Aggregator::new();
    let result = aggregator.aggregate(&bundle, &tsl);
    
    assert!(result.is_ok(), "Aggregate proof generation should succeed");
    
    let proof = result.unwrap();
    assert_eq!(proof.num_signatures, 3, "Proof should contain 3 signatures");
}

#[test]
fn test_message_hash_compatibility() {
    let message = b"test message";
    
    // Hash using Poseidon2Hash
    let hasher = Poseidon2Hash::new();
    let hash1 = hasher.hash(message);
    
    // Hash using Aggregator's method
    let hash2 = Aggregator::hash_message(message);
    
    // Convert hash2 to bytes for comparison
    let mut hash2_bytes = Vec::new();
    for element in hash2.elements.iter() {
        use plonky2::field::types::PrimeField64;
        let bytes = element.to_noncanonical_u64().to_le_bytes();
        hash2_bytes.extend_from_slice(&bytes);
    }
    
    assert_eq!(hash1, hash2_bytes, "Hash methods should produce same result");
}

#[test]
fn test_empty_signature_bundle() {
    let result = SignatureBundle::new(vec![], vec![], b"message".to_vec());
    assert!(result.is_ok(), "Empty bundle should be valid");
    
    let bundle = result.unwrap();
    assert!(bundle.is_empty(), "Bundle should be empty");
}

#[test]
fn test_mismatched_signature_count() {
    let params = WotsParams::new(16, 32);
    let keypair = WotsKeypair::generate(&params);
    
    let message_digest: Vec<usize> = (1..=32).map(|i| (i % 15) + 1).collect();
    let signature = keypair.sign(&message_digest);
    
    // Try to create bundle with mismatched counts
    let result = SignatureBundle::new(
        vec![signature],
        vec![keypair.public_key().clone(), keypair.public_key().clone()],
        b"message".to_vec(),
    );
    
    assert!(result.is_err(), "Mismatched counts should fail");
}

#[cfg(test)]
mod aggregate_verification_tests {
    
    #[test]
    fn test_public_inputs_serialization() {
        use hypercube_signatures::aggregate::{PublicInputs, F};
        use plonky2::field::types::Field;
        
        let message_hash = vec![F::ONE, F::TWO, F::ZERO, F::ONE];
        let pk_commitments = vec![
            vec![F::ONE, F::ZERO, F::ONE, F::TWO],
            vec![F::TWO, F::ONE, F::ZERO, F::ONE],
        ];
        
        let public_inputs = PublicInputs {
            message_hash: message_hash.clone(),
            public_key_commitments: pk_commitments.clone(),
        };
        
        let serialized = public_inputs.to_field_elements();
        assert_eq!(serialized.len(), 12, "Should have 4 + 2*4 elements");
        
        // Test deserialization
        let deserialized = PublicInputs::from_field_elements(&serialized, 2, 4)
            .expect("Deserialization should succeed");
        
        assert_eq!(deserialized.message_hash, message_hash);
        assert_eq!(deserialized.public_key_commitments, pk_commitments);
    }
}