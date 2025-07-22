// TLFC (Top Layers with Full Checksum) implementation
//
/// Paper Construction 2:Top Layers with a Full Checksum
// TLFC maps messages to multiple layers [0, d₀] with c checksum chains.
// This provides the best verification efficiency at the cost of c extra chains.
use crate::core::encoding::{EncodingScheme, NonUniformMapping};
use crate::core::hypercube::{Hypercube, Vertex};
use crate::core::mapping::{calculate_layer_size, integer_to_vertex};
use crate::crypto::hash::{HashFunction, SHA256};
use num_traits::ToPrimitive;

/// TLFC configuration parameters
#[derive(Debug, Clone)]
pub struct TLFCConfig {
    w: usize,
    v: usize,
    d0: usize,
    c: usize, // Paper: Number of checksum chains (optimization parameter)
}

impl TLFCConfig {
    /// Create TLFC config for given security level
    pub fn new(security_bits: usize) -> Self {
        // For TLFC, we need ℓ_{[0:d₀]} ≥ 2^λ
        // The number of checksum chains c is an optimization parameter
        // Try different parameter combinations
        let candidates = vec![
            (16, 16, 4), // w=16, v=16, c=4
            (32, 12, 3), // w=32, v=12, c=3
            (64, 8, 2),  // w=64, v=8, c=2
        ];

        for (w, v, c) in candidates {
            // Find appropriate d0 such that sum of layer sizes ≥ 2^λ
            for d0 in 1..=(v * (w - 1)) {
                // Try to calculate total size with overflow protection
                let mut total_size_option = Some(0usize);
                for d in 0..=d0 {
                    if let Some(current_total) = total_size_option {
                        let layer_size_big = calculate_layer_size(d, v, w).unwrap();
                        if let Some(layer_size) = layer_size_big.to_usize() {
                            total_size_option = current_total.checked_add(layer_size);
                        } else {
                            total_size_option = None;
                            break;
                        }
                    }
                }

                if let Some(total_size) = total_size_option {
                    if total_size > 0 && (total_size as f64).log2() >= security_bits as f64 {
                        return TLFCConfig { w, v, d0, c };
                    }
                }
            }
        }

        // Fallback
        TLFCConfig {
            w: 16,
            v: 32,
            d0: 10,
            c: 4,
        }
    }

    /// Create TLFC config with specific parameters
    pub fn with_params(w: usize, v: usize, d0: usize, c: usize) -> Self {
        assert!(w > 1, "w must be greater than 1");
        assert!(v > 0, "v must be positive");
        assert!(d0 <= v * (w - 1), "d0 must be valid layer");
        assert!(c > 0, "c must be positive");
        assert!(c <= v, "c cannot exceed v");

        TLFCConfig { w, v, d0, c }
    }

    pub fn w(&self) -> usize {
        self.w
    }

    pub fn v(&self) -> usize {
        self.v
    }

    pub fn d0(&self) -> usize {
        self.d0
    }

    pub fn c(&self) -> usize {
        self.c
    }

    pub fn signature_chains(&self) -> usize {
        self.v + self.c // TLFC has c checksum chains
    }
}

/// TLFC encoding scheme
/// Paper Algorithm TLFC (Section 2.3): Maps messages to layers [0, d₀] with full checksum
pub struct TLFC {
    config: TLFCConfig,
    hasher: SHA256,
    total_layer_size: usize,
}

impl TLFC {
    pub fn new(config: TLFCConfig) -> Self {
        // Calculate total size of layers [0, d0] with overflow protection
        let mut total_layer_size = 0usize;
        for d in 0..=config.d0 {
            let layer_size_big = calculate_layer_size(d, config.v, config.w).unwrap();
            let layer_size = layer_size_big
                .to_usize()
                .expect("Layer size too large to fit in usize");
            total_layer_size = total_layer_size
                .checked_add(layer_size)
                .expect("Total layer size overflow");
        }

        assert!(total_layer_size > 0, "Total layer size must be positive");

        TLFC {
            config,
            hasher: SHA256::new(),
            total_layer_size,
        }
    }

    /// Encode message with full checksum
    pub fn encode_with_checksum(&self, message: &[u8], randomness: &[u8]) -> (Vertex, Vec<usize>) {
        let vertex = self.encode(message, randomness);
        let checksums = self.calculate_full_checksum(vertex.components());
        (vertex, checksums)
    }

    /// Calculate full checksum for vertex components
    /// Full checksum with c chains
    pub fn calculate_full_checksum(&self, components: &[usize]) -> Vec<usize> {
        let w = self.config.w;
        let c = self.config.c;
        let mut checksums = vec![0; c];

        // Paper Eq. (3): C_i = Σ_{j: j mod c = i} 2^(j mod c) * (w - a_j)
        for (j, &a_j) in components.iter().enumerate() {
            let i = j % c;
            checksums[i] += (1 << (j % c)) * (w - a_j);
        }

        // Paper: Normalize checksums to fit in alphabet [w]
        // Implementation detail: map to [1, w] range
        for checksum in &mut checksums {
            *checksum = (*checksum % w) + 1;
        }

        checksums
    }

    /// Map to top layers [0, d0]
    /// Uniform mapping to the union of layers [0, d₀]
    /// Same distribution as TL1C but with different checksum computation
    pub fn map_to_top_layers(&self, value: usize) -> Vertex {
        // Map uniformly to layers [0, d0]
        let index = value % self.total_layer_size;

        // Find which layer this index falls into
        let mut cumulative = 0;
        for d in 0..=self.config.d0 {
            let layer_size = calculate_layer_size(d, self.config.v, self.config.w)
                .unwrap()
                .to_usize()
                .unwrap();
            if index < cumulative + layer_size {
                // Index is in layer d
                let layer_index = index - cumulative;
                let components = integer_to_vertex(layer_index, self.config.w, self.config.v, d)
                    .unwrap_or_else(|_| vec![self.config.w; self.config.v]);
                return Vertex::new(components);
            }
            cumulative += layer_size;
        }

        // Should not reach here
        panic!("Index out of range");
    }

    /// Convert message to WOTS digest including checksums
    /// The WOTS message is (a₁, ..., aᵥ, C₁, ..., C_c)
    /// where (a₁, ..., aᵥ) is the encoded vertex and C₁, ..., C_c are the checksums.
    pub fn message_to_wots_digest(&self, message: &[u8], randomness: &[u8]) -> Vec<usize> {
        let (vertex, checksums) = self.encode_with_checksum(message, randomness);

        let mut digest = vertex.components().clone();
        digest.extend(checksums);

        digest
    }

    fn encode(&self, message: &[u8], randomness: &[u8]) -> Vertex {
        // H(m || r)
        let mut input = Vec::new();
        input.extend_from_slice(message);
        input.extend_from_slice(randomness);

        let hash = self.hasher.hash(&input);

        // Convert hash to integer
        let mut value = 0usize;
        for (i, &byte) in hash.iter().enumerate().take(8) {
            value |= (byte as usize) << (i * 8);
        }

        // Map to top layers
        self.map_to_top_layers(value)
    }
}

impl EncodingScheme for TLFC {
    fn encode(&self, message: &[u8], randomness: &[u8]) -> Vertex {
        self.encode(message, randomness)
    }

    fn alphabet_size(&self) -> usize {
        self.config.w
    }

    fn dimension(&self) -> usize {
        self.config.v
    }
}

impl NonUniformMapping for TLFC {
    /// Paper Section 4: Implementation of the non-uniform mapping Ψ for TLFC
    fn map(&self, value: usize) -> Vertex {
        self.map_to_top_layers(value)
    }

    /// For TLFC, Pr[Ψ(z) = x] = 1/ℓ_{[0:d₀]} if x ∈ layers [0,d₀], else 0
    /// Same distribution as TL1C but achieves better efficiency through the full checksum.
    fn probability(&self, vertex: &Vertex) -> f64 {
        let hc = Hypercube::new(self.config.w, self.config.v);
        let layer = hc.calculate_layer(vertex);

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
    fn test_tlfc_config_creation() {
        // Test TLFC configuration creation
        let config = TLFCConfig::new(128); // 128-bit security

        assert!(config.w() > 0);
        assert!(config.v() > 0);
        assert!(config.d0() > 0);
        assert!(config.c() > 0); // Number of checksum chains

        // Check that total layer size calculation succeeds
        let mut total_size_option = Some(0usize);
        for d in 0..=config.d0() {
            if let Some(current_total) = total_size_option {
                let layer_size_big = calculate_layer_size(d, config.v(), config.w()).unwrap();
                if let Some(layer_size) = layer_size_big.to_usize() {
                    total_size_option = current_total.checked_add(layer_size);
                } else {
                    total_size_option = None;
                    break;
                }
            }
        }

        assert!(total_size_option.is_some() && total_size_option.unwrap() > 0);
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
            assert!(
                layer_counts[layer] > 0,
                "Layer {} should have vertices",
                layer
            );
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
}
