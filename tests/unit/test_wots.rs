use hypercube_signatures::wots::{WotsSignature, WotsParams, WotsKeypair};
use hypercube_signatures::crypto::hash::HashFunction;

#[test]
fn test_wots_params() {
    // Test WOTS parameter creation
    let params = WotsParams::new(4, 64); // w=4, v=64
    
    assert_eq!(params.w(), 4);
    assert_eq!(params.chains(), 64);
    assert_eq!(params.max_hash_iterations(), 3); // w-1 = 3
}

#[test]
fn test_wots_keygen() {
    let params = WotsParams::new(4, 8); // Small params for testing
    let keypair = WotsKeypair::generate(&params);
    
    // Check key sizes
    assert_eq!(keypair.public_key().chains().len(), 8);
    assert_eq!(keypair.secret_key().chains().len(), 8);
    
    // Verify public key is H^{w-1}(secret key)
    // This is checked internally, but we can verify the structure
    for i in 0..8 {
        assert_eq!(keypair.public_key().chains()[i].len(), 32); // SHA256 output
        assert_eq!(keypair.secret_key().chains()[i].len(), 32);
    }
}

#[test]
fn test_wots_sign_verify() {
    let params = WotsParams::new(4, 8);
    let keypair = WotsKeypair::generate(&params);
    
    // Create a message digest (would come from encoding in real use)
    let message_digest = vec![2, 3, 1, 4, 2, 3, 1, 4]; // Values in [1,4]
    
    // Sign
    let signature = keypair.sign(&message_digest);
    
    // Verify
    assert!(keypair.public_key().verify(&message_digest, &signature));
}

#[test]
fn test_wots_wrong_message() {
    let params = WotsParams::new(4, 8);
    let keypair = WotsKeypair::generate(&params);
    
    let message_digest = vec![2, 3, 1, 4, 2, 3, 1, 4];
    let wrong_message = vec![1, 3, 1, 4, 2, 3, 1, 4]; // Changed first element
    
    let signature = keypair.sign(&message_digest);
    
    // Verification should fail for wrong message
    assert!(!keypair.public_key().verify(&wrong_message, &signature));
}

#[test]
fn test_wots_signature_size() {
    let params = WotsParams::new(4, 64);
    let keypair = WotsKeypair::generate(&params);
    
    let message_digest = vec![2; 64]; // All 2s
    let signature = keypair.sign(&message_digest);
    
    // Signature should have 64 chains
    assert_eq!(signature.chains().len(), 64);
    
    // Each chain should be a hash value
    for chain in signature.chains() {
        assert_eq!(chain.len(), 32); // SHA256 output
    }
}

#[test]
fn test_wots_hash_chain_computation() {
    use hypercube_signatures::crypto::hash::SHA256;
    
    let hasher = SHA256::new();
    let input = vec![0x42; 32]; // 32 bytes of 0x42
    
    // Test H^0(x) = x
    let h0 = hypercube_signatures::wots::hash_chain(&hasher, &input, 0);
    assert_eq!(h0, input);
    
    // Test H^1(x) = H(x)
    let h1 = hypercube_signatures::wots::hash_chain(&hasher, &input, 1);
    let expected_h1 = hasher.hash(&input);
    assert_eq!(h1, expected_h1);
    
    // Test H^3(x) = H(H(H(x)))
    let h3 = hypercube_signatures::wots::hash_chain(&hasher, &input, 3);
    let temp1 = hasher.hash(&input);
    let temp2 = hasher.hash(&temp1);
    let expected_h3 = hasher.hash(&temp2);
    assert_eq!(h3, expected_h3);
}

#[test]
fn test_wots_deterministic_signing() {
    let params = WotsParams::new(4, 8);
    let keypair = WotsKeypair::generate(&params);
    
    let message_digest = vec![2, 3, 1, 4, 2, 3, 1, 4];
    
    // Same message should produce same signature
    let sig1 = keypair.sign(&message_digest);
    let sig2 = keypair.sign(&message_digest);
    
    assert_eq!(sig1.chains(), sig2.chains());
}

#[test]
fn test_wots_security_property() {
    // Test one-time security property
    // If we sign two different messages with same key, 
    // an attacker might be able to forge
    let params = WotsParams::new(4, 4); // Small for testing
    let keypair = WotsKeypair::generate(&params);
    
    let msg1 = vec![1, 2, 3, 4];
    let msg2 = vec![2, 3, 4, 1];
    
    let sig1 = keypair.sign(&msg1);
    let sig2 = keypair.sign(&msg2);
    
    // Both signatures should verify
    assert!(keypair.public_key().verify(&msg1, &sig1));
    assert!(keypair.public_key().verify(&msg2, &sig2));
    
    // But signing two messages reveals information
    // (In practice, this key should never be used again)
}