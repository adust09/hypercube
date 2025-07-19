use hypercube_signatures::aggregate::SignatureBundle;
use hypercube_signatures::aggregate::aggregator_simple::SimpleAggregator;
use hypercube_signatures::wots::{WotsParams, WotsKeypair};

#[test]
fn test_simple_aggregate_circuit() {
    // Create minimal test data
    let params = WotsParams::new(4, 4); // Small parameters for testing
    let message = b"test";
    
    let mut signatures = Vec::new();
    let mut public_keys = Vec::new();
    
    // Generate just 1 signature for simplicity
    let keypair = WotsKeypair::generate(&params);
    let message_digest = vec![1, 2, 3, 4]; // Simple digest
    let signature = keypair.sign(&message_digest);
    
    signatures.push(signature);
    public_keys.push(keypair.public_key().clone());
    
    let bundle = SignatureBundle::new(signatures, public_keys, message.to_vec())
        .expect("Failed to create signature bundle");
    
    // Create simple aggregator
    let aggregator = SimpleAggregator::new();
    
    // Test simple aggregation
    let result = aggregator.aggregate_simple(&bundle);
    
    assert!(result.is_ok(), "Simple aggregation should succeed");
    
    let proof = result.unwrap();
    assert_eq!(proof.num_signatures, 1, "Proof should contain 1 signature");
}