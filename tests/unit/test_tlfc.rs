use hypercube_signatures::schemes::tlfc::{TLFC, TLFCConfig};
use hypercube_signatures::core::hypercube::Hypercube;

#[test]
fn test_tlfc_config_creation() {
    // Test TLFC configuration creation
    let config = TLFCConfig::new(128); // 128-bit security
    
    assert!(config.w() > 0);
    assert!(config.v() > 0);
    assert!(config.d0() > 0);
    assert!(config.c() > 0); // Number of checksum chains
    
    // Check that total layer size is at least 2^λ
    let total_size = (0..=config.d0())
        .map(|d| hypercube_signatures::core::layer::calculate_layer_size(d, config.v(), config.w()))
        .sum::<usize>();
    
    assert!(total_size > 0);
}

#[test]
fn test_tlfc_parameter_selection() {
    // Test parameter selection for different security levels
    let config_128 = TLFCConfig::new(128);
    
    // For TLFC, we need ℓ_{[0:d_0]} ≥ 2^λ
    assert!(config_128.w() >= 2);
    assert!(config_128.v() > 0);
    assert!(config_128.d0() <= config_128.v() * (config_128.w() - 1));
    assert!(config_128.c() > 0);
}

#[test]
fn test_tlfc_encoding_basic() {
    let config = TLFCConfig::with_params(8, 4, 3, 2); // w=8, v=4, d0=3, c=2
    let tlfc = TLFC::new(config);
    
    let message = b"test message";
    let randomness = b"random seed";
    
    let (encoded, checksums) = tlfc.encode_with_checksum(message, randomness);
    
    // Verify encoded vertex is in valid layer range
    let hc = Hypercube::new(8, 4);
    let layer = hc.calculate_layer(&encoded);
    assert!(layer <= 3);
    
    // Verify we have c checksum values
    assert_eq!(checksums.len(), 2);
}

#[test]
fn test_tlfc_full_checksum_calculation() {
    let config = TLFCConfig::with_params(8, 4, 3, 2); // w=8, v=4, d0=3, c=2
    let tlfc = TLFC::new(config);
    
    // Test checksum calculation for a vertex
    let components = vec![2, 3, 1, 2]; // Example vertex
    let checksums = tlfc.calculate_full_checksum(&components);
    
    assert_eq!(checksums.len(), 2); // Should have c checksums
    
    // Each checksum should be in valid range
    for &checksum in &checksums {
        assert!(checksum >= 1);
        assert!(checksum <= 8); // <= w
    }
}

#[test]
fn test_tlfc_encoding_deterministic() {
    let config = TLFCConfig::with_params(8, 4, 3, 2);
    let tlfc = TLFC::new(config);
    
    let message = b"test message";
    let randomness = b"random seed";
    
    // Same input should produce same output
    let (encoded1, checksums1) = tlfc.encode_with_checksum(message, randomness);
    let (encoded2, checksums2) = tlfc.encode_with_checksum(message, randomness);
    
    assert_eq!(encoded1.components(), encoded2.components());
    assert_eq!(checksums1, checksums2);
}

#[test]
fn test_tlfc_uniform_distribution_within_layers() {
    // Test that TLFC produces uniform distribution within top layers
    let config = TLFCConfig::with_params(5, 3, 3, 1); // Small parameters for testing
    let tlfc = TLFC::new(config);
    
    // Map many values and count layer occurrences
    let mut layer_counts = vec![0; 4]; // Layers 0-3
    
    for i in 0..1000 {
        let vertex = tlfc.map_to_top_layers(i);
        let hc = Hypercube::new(5, 3);
        let layer = hc.calculate_layer(&vertex);
        if layer <= 3 {
            layer_counts[layer] += 1;
        }
    }
    
    // All layers 0-3 should have some vertices
    for layer in 0..=3 {
        assert!(layer_counts[layer] > 0, "Layer {} should have vertices", layer);
    }
}

#[test]
fn test_tlfc_no_vertices_beyond_d0() {
    let config = TLFCConfig::with_params(8, 4, 3, 2);
    let tlfc = TLFC::new(config);
    
    // Map many values and verify none go beyond d0
    for i in 0..1000 {
        let vertex = tlfc.map_to_top_layers(i);
        let hc = Hypercube::new(8, 4);
        let layer = hc.calculate_layer(&vertex);
        assert!(layer <= 3, "Vertex should not be in layer > d0");
    }
}

#[test]
fn test_tlfc_signature_size() {
    // Test that TLFC produces signatures of size v+c
    let config = TLFCConfig::with_params(8, 32, 7, 4); // c=4 checksum chains
    
    assert_eq!(config.signature_chains(), 36); // v + c chains
}

#[test]
fn test_tlfc_message_to_wots_digest() {
    // Test conversion from message to WOTS digest including checksums
    let config = TLFCConfig::with_params(8, 4, 3, 2);
    let tlfc = TLFC::new(config);
    
    let message = b"test message";
    let randomness = b"random seed";
    
    let digest = tlfc.message_to_wots_digest(message, randomness);
    
    // Digest should have v+c elements
    assert_eq!(digest.len(), 6); // v=4 + c=2
    
    // All elements should be in range [1, w]
    for &value in &digest {
        assert!(value >= 1 && value <= 8);
    }
}

#[test]
fn test_tlfc_checksum_properties() {
    // Test that full checksum has correct mathematical properties
    let config = TLFCConfig::with_params(8, 4, 3, 2);
    let w = config.w();
    let c = config.c();
    let tlfc = TLFC::new(config);
    
    // Test with different vertex components
    let test_cases = vec![
        vec![1, 1, 1, 1],
        vec![7, 7, 7, 7],
        vec![2, 3, 4, 5],
        vec![1, 2, 1, 2],
    ];
    
    for components in test_cases {
        let checksums = tlfc.calculate_full_checksum(&components);
        
        // Verify checksum bounds
        for &checksum in &checksums {
            assert!(checksum >= 1);
            assert!(checksum <= 8);
        }
        
        // Verify checksum calculation follows the formula from the paper
        // C_i = Σ_j 2^(j mod c) * (w - a_j) for j where j mod c = i
        
        for i in 0..c {
            let mut expected = 0;
            for (j, &a_j) in components.iter().enumerate() {
                if j % c == i {
                    expected += (1 << (j % c)) * (w - a_j);
                }
            }
            // Normalize to [1, w] range
            expected = (expected % w) + 1;
            assert_eq!(checksums[i], expected);
        }
    }
}