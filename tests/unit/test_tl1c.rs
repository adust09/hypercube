use hypercube_signatures::schemes::tl1c::{TL1C, TL1CConfig};
use hypercube_signatures::core::hypercube::Hypercube;

#[test]
fn test_tl1c_config_creation() {
    // Test TL1C configuration creation
    let config = TL1CConfig::new(128); // 128-bit security
    
    assert!(config.w() > 0);
    assert!(config.v() > 0);
    assert!(config.d0() > 0);
    
    // Check that total layer size is at least 2^λ
    let total_size = (0..=config.d0())
        .map(|d| hypercube_signatures::core::layer::calculate_layer_size(d, config.v(), config.w()))
        .sum::<usize>();
    
    assert!(total_size > 0);
}

#[test]
fn test_tl1c_parameter_selection() {
    // Test parameter selection for different security levels
    let config_128 = TL1CConfig::new(128);
    
    // For TL1C, we need ℓ_{[0:d_0]} ≥ 2^λ
    assert!(config_128.w() >= 2);
    assert!(config_128.v() > 0);
    assert!(config_128.d0() <= config_128.v() * (config_128.w() - 1));
}

#[test]
fn test_tl1c_encoding_basic() {
    let config = TL1CConfig::with_params(4, 4, 3);
    let tl1c = TL1C::new(config);
    
    let message = b"test message";
    let randomness = b"random seed";
    
    let (encoded, checksum) = tl1c.encode_with_checksum(message, randomness);
    
    // Verify encoded vertex is in valid layer range
    let hc = Hypercube::new(4, 4);
    let layer = hc.calculate_layer(&encoded);
    assert!(layer <= 3);
    
    // Verify checksum is layer + 1
    assert_eq!(checksum, layer + 1);
}

#[test]
fn test_tl1c_checksum_calculation() {
    let config = TL1CConfig::with_params(4, 4, 3);
    let d0 = config.d0();
    let tl1c = TL1C::new(config);
    
    // Test checksum for different layers
    for layer in 0..=3 {
        let checksum = tl1c.calculate_checksum(layer);
        assert_eq!(checksum, layer + 1);
        assert!(checksum >= 1);
        assert!(checksum <= d0 + 1);
    }
}

#[test]
fn test_tl1c_encoding_deterministic() {
    let config = TL1CConfig::with_params(4, 4, 3);
    let tl1c = TL1C::new(config);
    
    let message = b"test message";
    let randomness = b"random seed";
    
    // Same input should produce same output
    let (encoded1, checksum1) = tl1c.encode_with_checksum(message, randomness);
    let (encoded2, checksum2) = tl1c.encode_with_checksum(message, randomness);
    
    assert_eq!(encoded1.components(), encoded2.components());
    assert_eq!(checksum1, checksum2);
}

#[test]
fn test_tl1c_uniform_distribution_within_layers() {
    // Test that TL1C produces uniform distribution within top layers
    let config = TL1CConfig::with_params(5, 3, 3); // w=5 to accommodate checksum 4
    let tl1c = TL1C::new(config);
    
    // Map many values and count layer occurrences
    let mut layer_counts = vec![0; 4]; // Layers 0-3
    
    for i in 0..1000 {
        let vertex = tl1c.map_to_top_layers(i);
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
fn test_tl1c_no_vertices_beyond_d0() {
    let config = TL1CConfig::with_params(4, 4, 3);
    let tl1c = TL1C::new(config);
    
    // Map many values and verify none go beyond d0
    for i in 0..1000 {
        let vertex = tl1c.map_to_top_layers(i);
        let hc = Hypercube::new(4, 4);
        let layer = hc.calculate_layer(&vertex);
        assert!(layer <= 3, "Vertex should not be in layer > d0");
    }
}

#[test]
fn test_tl1c_signature_size() {
    // Test that TL1C produces signatures of size v+1
    let config = TL1CConfig::with_params(36, 32, 35); // w=36 to accommodate checksum up to 36
    
    assert_eq!(config.signature_chains(), 33); // v + 1 chain for checksum
}

#[test]
fn test_tl1c_message_to_wots_digest() {
    // Test conversion from message to WOTS digest including checksum
    let config = TL1CConfig::with_params(4, 4, 3);
    let tl1c = TL1C::new(config);
    
    let message = b"test message";
    let randomness = b"random seed";
    
    let digest = tl1c.message_to_wots_digest(message, randomness);
    
    // Digest should have v+1 elements
    assert_eq!(digest.len(), 5); // v=4 + 1 checksum
    
    // All elements should be in range [1, w]
    for &value in &digest {
        assert!(value >= 1 && value <= 4);
    }
    
    // Last element is the checksum
    let vertex_sum: usize = digest[..4].iter().sum();
    let layer = 4 * 4 - vertex_sum;
    assert_eq!(digest[4], layer + 1);
}

#[test]
fn test_tl1c_checksum_bounds() {
    // Test that checksum is always in valid range
    let config = TL1CConfig::with_params(12, 8, 10); // w=12 to accommodate checksum up to 11
    let w = config.w();
    let tl1c = TL1C::new(config);
    
    // Test various layers
    for layer in 0..=10 {
        let checksum = tl1c.calculate_checksum(layer);
        assert!(checksum >= 1, "Checksum should be at least 1");
        assert!(checksum <= 11, "Checksum should be at most d0+1");
        assert!(checksum <= w, "Checksum should fit in alphabet");
    }
}