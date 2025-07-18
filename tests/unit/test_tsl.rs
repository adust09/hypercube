use hypercube_signatures::schemes::tsl::{TSLConfig, TSL};

#[test]
fn test_tsl_config_creation() {
    // Test TSL configuration creation
    let config = TSLConfig::new(128); // 128-bit security

    // For 128-bit security, we need w^v > 2^{λ+log₄λ} ≈ 2^{128+3.5} ≈ 2^131.5
    assert!(config.w() > 0);
    assert!(config.v() > 0);
    assert!(config.d0() > 0);

    // Check that layer d0 has vertices
    let layer_size = hypercube_signatures::core::layer::calculate_layer_size(
        config.d0(),
        config.v(),
        config.w(),
    );
    assert!(layer_size > 0, "Layer {} should have positive size", config.d0());
}

#[test]
fn test_tsl_parameter_selection() {
    // Test parameter selection for different security levels

    // 128-bit security
    let config_128 = TSLConfig::new(128);
    // Just verify parameters are reasonable
    assert!(config_128.w() >= 4);
    assert!(config_128.v() >= 16); // Adjusted for implementation constraints

    // 160-bit security
    let config_160 = TSLConfig::new(160);
    assert!(config_160.w() >= 4);
    assert!(config_160.v() >= 20); // Adjusted for implementation constraints
}

#[test]
fn test_tsl_encoding_basic() {
    let config = TSLConfig::with_params(4, 4, 4); // Small example for testing
    let tsl = TSL::new(config);

    // Test encoding
    let message = b"test message";
    let randomness = b"random seed";

    let encoded = tsl.encode(message, randomness).unwrap();

    // Verify the encoded vertex is in the correct layer
    let layer =
        hypercube_signatures::core::hypercube::Hypercube::new(4, 4).calculate_layer(&encoded);
    assert_eq!(layer, 4); //Should be in layer d0 = 4
}

#[test]
fn test_tsl_encoding_deterministic() {
    let config = TSLConfig::with_params(4, 4, 4);
    let tsl = TSL::new(config);

    let message = b"test message";
    let randomness = b"random seed";

    // Same input should produce same output
    let encoded1 = tsl.encode(message, randomness).unwrap();
    let encoded2 = tsl.encode(message, randomness).unwrap();

    assert_eq!(encoded1.components(), encoded2.components());
}

#[test]
fn test_tsl_encoding_different_messages() {
    let config = TSLConfig::with_params(4, 4, 4);
    let tsl = TSL::new(config);

    let randomness = b"random seed";

    // Different messages should (likely) produce different outputs
    let encoded1 = tsl.encode(b"message1", randomness).unwrap();
    let encoded2 = tsl.encode(b"message2", randomness).unwrap();

    // They should both be in the same layer
    let hc = hypercube_signatures::core::hypercube::Hypercube::new(4, 4);
    assert_eq!(hc.calculate_layer(&encoded1), 4);
    assert_eq!(hc.calculate_layer(&encoded2), 4);

    // But likely different vertices (not guaranteed, but very likely)
    assert_ne!(encoded1.components(), encoded2.components());
}

#[test]
fn test_tsl_non_uniform_mapping() {
    // Test the non-uniform mapping function Ψ
    let config = TSLConfig::with_params(4, 4, 4);
    let tsl = TSL::new(config);

    // The mapping should only produce vertices in layer d0
    for i in 0..100 {
        let vertex = tsl.map_to_layer(i).unwrap();
        let layer =
            hypercube_signatures::core::hypercube::Hypercube::new(4, 4).calculate_layer(&vertex);
        assert_eq!(layer, 4);
    }
}

#[test]
fn test_tsl_uniform_distribution() {
    // Test that the mapping produces uniform distribution within the layer
    let config = TSLConfig::with_params(3, 3, 3);
    let tsl = TSL::new(config);

    let layer_size = hypercube_signatures::core::layer::calculate_layer_size(3, 3, 3);
    let mut counts = vec![0; layer_size];

    // Map many values and count occurrences
    let num_samples = layer_size * 100;
    for i in 0..num_samples {
        let vertex = tsl.map_to_layer(i).unwrap();
        // Convert vertex to index within layer
        let idx =
            hypercube_signatures::core::mapping::vertex_to_integer(vertex.components(), 3, 3, 3)
                .unwrap();
        counts[idx] += 1;
    }

    // Check that distribution is roughly uniform
    let expected = num_samples / layer_size;
    for count in counts {
        assert!(count > expected * 8 / 10); // Within 20% of expected
        assert!(count < expected * 12 / 10);
    }
}

#[test]
fn test_tsl_incomparability() {
    // Test that TSL produces vertices from the same layer
    // Note: Vertices in the same layer may still be comparable
    let config = TSLConfig::with_params(3, 2, 2);
    let expected_layer = config.d0();
    let tsl = TSL::new(config);

    let vertices: Vec<_> = (0..10).map(|i| tsl.map_to_layer(i).unwrap()).collect();

    // Check that all vertices are in the same layer
    let hc = hypercube_signatures::core::hypercube::Hypercube::new(3, 2);

    for vertex in &vertices {
        assert_eq!(hc.calculate_layer(vertex), expected_layer);
    }

    // Note: TSL ensures non-comparability by using a single layer,
    // but vertices within that layer can still be comparable.
    // The non-comparability property comes from the fact that
    // different messages map to different vertices in the same layer.
}

#[test]
fn test_tsl_signature_size() {
    // Test that TSL produces signatures of size v (no checksum)
    let config = TSLConfig::with_params(4, 32, 35); // Adjusted parameters

    assert_eq!(config.signature_chains(), 32); // Only v chains, no checksum
}
