// TL1C (Top Layers with 1-Chain Checksum) implementation
//
/// Paper Construction 3:Top Layers with a 1-Chain Checksum
// TL1C maps messages to multiple layers [0, d₀] with a single checksum chain.
// This provides better verification efficiency than TSL at the cost of one extra chain.
use crate::core::encoding::{EncodingScheme, NonUniformMapping};
use crate::core::hypercube::{Hypercube, Vertex};
use crate::core::mapping::{calculate_layer_size, integer_to_vertex};
use crate::crypto::hash::{HashFunction, SHA256};
use num_traits::ToPrimitive;

/// TL1C configuration parameters
#[derive(Debug, Clone,)]
pub struct TL1CConfig {
    w: usize,
    v: usize,
    d0: usize,
}

impl TL1CConfig {
    /// Create TL1C config for given security level
    pub fn new(security_bits: usize,) -> Self {
        // For TL1C, we need ℓ_{[0:d₀]} ≥ 2^λ
        // where ℓ_{[0:d₀]} = Σ_{d=0}^{d₀} ℓ_d
        // Try different parameter combinations
        // Note: w must be large enough to accommodate checksum d0+1
        let candidates = vec![
            (16, 16,), // w=16, v=16
            (32, 12,), // w=32, v=12
            (64, 8,),  // w=64, v=8
        ];

        for (w, v,) in candidates {
            // Find appropriate d0 such that sum of layer sizes ≥ 2^λ
            for d0 in 1..=(v * (w - 1)) {
                // Try to calculate total size with overflow protection
                let mut total_size_option = Some(0usize,);
                for d in 0..=d0 {
                    if let Some(current_total,) = total_size_option {
                        let layer_size_big = calculate_layer_size(d, v, w,).unwrap();
                        if let Some(layer_size,) = layer_size_big.to_usize() {
                            total_size_option = current_total.checked_add(layer_size,);
                        } else {
                            total_size_option = None;
                            break;
                        }
                    }
                }

                if let Some(total_size,) = total_size_option {
                    if total_size > 0 && (total_size as f64).log2() >= security_bits as f64 {
                        // Paper: Checksum C = d + 1 must satisfy C ∈ [w]
                        // So we need d₀ + 1 ≤ w
                        if d0 + 1 <= w {
                            return TL1CConfig { w, v, d0, };
                        }
                    }
                }
            }
        }

        // Fallback - use larger w to accommodate checksum
        TL1CConfig { w: 16, v: 32, d0: 10, }
    }

    /// Create TL1C config with specific parameters
    pub fn with_params(w: usize, v: usize, d0: usize,) -> Self {
        assert!(w > 1, "w must be greater than 1");
        assert!(v > 0, "v must be positive");
        assert!(d0 <= v * (w - 1), "d0 must be valid layer");
        assert!(d0 + 1 <= w, "Checksum d0+1 must fit in alphabet [1,w]");

        TL1CConfig { w, v, d0, }
    }

    pub fn w(&self,) -> usize {
        self.w
    }

    pub fn v(&self,) -> usize {
        self.v
    }

    pub fn d0(&self,) -> usize {
        self.d0
    }

    pub fn signature_chains(&self,) -> usize {
        self.v + 1 // TL1C has 1 checksum chain
    }
}

/// TL1C encoding scheme
pub struct TL1C {
    config: TL1CConfig,
    hasher: SHA256,
    total_layer_size: usize,
}

impl TL1C {
    pub fn new(config: TL1CConfig,) -> Self {
        // Calculate total size of layers [0, d0] with overflow protection
        let mut total_layer_size = 0usize;
        for d in 0..=config.d0 {
            let layer_size_big = calculate_layer_size(d, config.v, config.w,).unwrap();
            let layer_size =
                layer_size_big.to_usize().expect("Layer size too large to fit in usize",);
            total_layer_size =
                total_layer_size.checked_add(layer_size,).expect("Total layer size overflow",);
        }

        assert!(total_layer_size > 0, "Total layer size must be positive");

        TL1C { config, hasher: SHA256::new(), total_layer_size, }
    }

    /// Encode message with 1-chain checksum
    pub fn encode_with_checksum(&self, message: &[u8], randomness: &[u8],) -> (Vertex, usize,) {
        let vertex = self.encode(message, randomness,);
        let hc = Hypercube::new(self.config.w, self.config.v,);
        let layer = hc.calculate_layer(&vertex,);
        let checksum = self.calculate_checksum(layer,);
        (vertex, checksum,)
    }

    /// Calculate checksum for a layer
    /// Paper Equation (2) (Section 2.2): C = d + 1
    /// The checksum encodes which layer the message was mapped to.
    pub fn calculate_checksum(&self, layer: usize,) -> usize {
        // Paper: Checksum C = d + 1 where d is the layer
        layer + 1
    }

    /// Map to top layers [0, d0]
    /// Paper Section 2.2: Uniform mapping to the union of layers [0, d₀]
    /// Each vertex in this set has probability 1/ℓ_{[0:d₀]}
    pub fn map_to_top_layers(&self, value: usize,) -> Vertex {
        // Map uniformly to layers [0, d0]
        let index = value % self.total_layer_size;

        // Find which layer this index falls into
        let mut cumulative = 0;
        for d in 0..=self.config.d0 {
            let layer_size =
                calculate_layer_size(d, self.config.v, self.config.w,).unwrap().to_usize().unwrap();
            if index < cumulative + layer_size {
                // Index is in layer d
                let layer_index = index - cumulative;
                let components = integer_to_vertex(layer_index, self.config.w, self.config.v, d,)
                    .unwrap_or_else(|_| vec![self.config.w; self.config.v],);
                return Vertex::new(components,);
            }
            cumulative += layer_size;
        }

        // Should not reach here
        panic!("Index out of range");
    }

    /// Convert message to WOTS digest including checksum
    /// Paper Section 2.2: The WOTS message is (a₁, ..., aᵥ, C)
    /// where (a₁, ..., aᵥ) is the encoded vertex and C = d + 1 is the checksum.
    pub fn message_to_wots_digest(&self, message: &[u8], randomness: &[u8],) -> Vec<usize,> {
        let (vertex, checksum,) = self.encode_with_checksum(message, randomness,);

        let mut digest = vertex.components().clone();
        digest.push(checksum,);

        digest
    }

    fn encode(&self, message: &[u8], randomness: &[u8],) -> Vertex {
        // H(m || r)
        let mut input = Vec::new();
        input.extend_from_slice(message,);
        input.extend_from_slice(randomness,);

        let hash = self.hasher.hash(&input,);

        // Convert hash to integer
        let mut value = 0usize;
        for (i, &byte,) in hash.iter().enumerate().take(8,) {
            value |= (byte as usize) << (i * 8);
        }

        // Map to top layers
        self.map_to_top_layers(value,)
    }
}

impl EncodingScheme for TL1C {
    fn encode(&self, message: &[u8], randomness: &[u8],) -> Vertex {
        self.encode(message, randomness,)
    }

    fn alphabet_size(&self,) -> usize {
        self.config.w
    }

    fn dimension(&self,) -> usize {
        self.config.v
    }
}

impl NonUniformMapping for TL1C {
    /// Implementation of the non-uniform mapping Ψ for TL1C
    fn map(&self, value: usize,) -> Vertex {
        self.map_to_top_layers(value,)
    }

    /// For TL1C, Pr[Ψ(z) = x] = 1/ℓ_{[0:d₀]} if x ∈ layers [0,d₀], else 0
    /// This distributes uniformly across all vertices in the top layers.
    fn probability(&self, vertex: &Vertex,) -> f64 {
        let hc = Hypercube::new(self.config.w, self.config.v,);
        let layer = hc.calculate_layer(vertex,);

        if layer <= self.config.d0 {
            // Paper: Uniform distribution within top layers [0, d₀]
            1.0 / self.total_layer_size as f64
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tl1c_config_creation() {
        // Test TL1C configuration creation
        let config = TL1CConfig::new(128,); // 128-bit security

        assert!(config.w() > 0);
        assert!(config.v() > 0);
        assert!(config.d0() > 0);

        // Check that total layer size calculation succeeds
        let mut total_size_option = Some(0usize,);
        for d in 0..=config.d0() {
            if let Some(current_total,) = total_size_option {
                let layer_size_big = calculate_layer_size(d, config.v(), config.w(),).unwrap();
                if let Some(layer_size,) = layer_size_big.to_usize() {
                    total_size_option = current_total.checked_add(layer_size,);
                } else {
                    total_size_option = None;
                    break;
                }
            }
        }

        assert!(total_size_option.is_some() && total_size_option.unwrap() > 0);
    }

    #[test]
    fn test_tl1c_parameter_selection() {
        // Test parameter selection for different security levels
        let config_128 = TL1CConfig::new(128,);

        // For TL1C, we need ℓ_{[0:d_0]} ≥ 2^λ
        assert!(config_128.w() >= 2);
        assert!(config_128.v() > 0);
        assert!(config_128.d0() <= config_128.v() * (config_128.w() - 1));
    }

    #[test]
    fn test_tl1c_encoding_basic() {
        let config = TL1CConfig::with_params(4, 4, 3,);
        let tl1c = TL1C::new(config,);

        let message = b"test message";
        let randomness = b"random seed";

        let (encoded, checksum,) = tl1c.encode_with_checksum(message, randomness,);

        // Verify encoded vertex is in valid layer range
        let hc = Hypercube::new(4, 4,);
        let layer = hc.calculate_layer(&encoded,);
        assert!(layer <= 3);

        // Verify checksum is layer + 1
        assert_eq!(checksum, layer + 1);
    }

    #[test]
    fn test_tl1c_checksum_calculation() {
        let config = TL1CConfig::with_params(4, 4, 3,);
        let d0 = config.d0();
        let tl1c = TL1C::new(config,);

        // Test checksum for different layers
        for layer in 0..=3 {
            let checksum = tl1c.calculate_checksum(layer,);
            assert_eq!(checksum, layer + 1);
            assert!(checksum >= 1);
            assert!(checksum <= d0 + 1);
        }
    }

    #[test]
    fn test_tl1c_encoding_deterministic() {
        let config = TL1CConfig::with_params(4, 4, 3,);
        let tl1c = TL1C::new(config,);

        let message = b"test message";
        let randomness = b"random seed";

        // Same input should produce same output
        let (encoded1, checksum1,) = tl1c.encode_with_checksum(message, randomness,);
        let (encoded2, checksum2,) = tl1c.encode_with_checksum(message, randomness,);

        assert_eq!(encoded1.components(), encoded2.components());
        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn test_tl1c_uniform_distribution_within_layers() {
        // Test that TL1C produces uniform distribution within top layers
        let config = TL1CConfig::with_params(5, 3, 3,); // w=5 to accommodate checksum 4
        let tl1c = TL1C::new(config,);

        // Map many values and count layer occurrences
        let mut layer_counts = vec![0; 4]; // Layers 0-3

        for i in 0..1000 {
            let vertex = tl1c.map_to_top_layers(i,);
            let hc = Hypercube::new(5, 3,);
            let layer = hc.calculate_layer(&vertex,);
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
        let config = TL1CConfig::with_params(4, 4, 3,);
        let tl1c = TL1C::new(config,);

        // Map many values and verify none go beyond d0
        for i in 0..1000 {
            let vertex = tl1c.map_to_top_layers(i,);
            let hc = Hypercube::new(4, 4,);
            let layer = hc.calculate_layer(&vertex,);
            assert!(layer <= 3, "Vertex should not be in layer > d0");
        }
    }

    #[test]
    fn test_tl1c_signature_size() {
        // Test that TL1C produces signatures of size v+1
        let config = TL1CConfig::with_params(36, 32, 35,); // w=36 to accommodate checksum up to 36

        assert_eq!(config.signature_chains(), 33); // v + 1 chain for checksum
    }

    #[test]
    fn test_tl1c_message_to_wots_digest() {
        // Test conversion from message to WOTS digest including checksum
        let config = TL1CConfig::with_params(4, 4, 3,);
        let tl1c = TL1C::new(config,);

        let message = b"test message";
        let randomness = b"random seed";

        let digest = tl1c.message_to_wots_digest(message, randomness,);

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
        let config = TL1CConfig::with_params(12, 8, 10,); // w=12 to accommodate checksum up to 11
        let w = config.w();
        let tl1c = TL1C::new(config,);

        // Test various layers
        for layer in 0..=10 {
            let checksum = tl1c.calculate_checksum(layer,);
            assert!(checksum >= 1, "Checksum should be at least 1");
            assert!(checksum <= 11, "Checksum should be at most d0+1");
            assert!(checksum <= w, "Checksum should fit in alphabet");
        }
    }
}
