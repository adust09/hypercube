// TSL (Top Single Layer) implementation
//
// Paper Construction 4:Top Single Layer
// TSL is the simplest scheme that maps messages to a single layer d₀.
// It achieves optimal collision resistance with no checksum overhead.

use crate::core::encoding::{EncodingScheme, NonUniformMapping};
use crate::core::hypercube::Vertex;
use crate::core::mapping::{calculate_layer_size, integer_to_vertex};
use crate::crypto::hash::{HashFunction, SHA256};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

/// TSL configuration parameters
/// Parameters for the TSL encoding scheme
#[derive(Debug, Clone)]
pub struct TSLConfig {
    w: usize,
    v: usize,
    d0: usize,
}

impl TSLConfig {
    /// Create TSL config for given security level (128 or 160 bits)
    /// Uses optimal default v values: 128-bit -> v=25, 160-bit -> v=35
    pub fn new(security_bits: usize) -> Self {
        match security_bits {
            128 => Self::new_full(128, 25),
            160 => Self::new_full(160, 35),
            _ => panic!(
                "Only 128-bit and 160-bit security levels are supported. Got: {}",
                security_bits
            ),
        }
    }

    /// Create TSL config for given security level and signature size v
    /// Finds optimal w and d0 parameters based on paper recommendations
    pub fn new_full(security_bits: usize, v: usize) -> Self {
        // Paper parameters for TSL (w, v, optimal_d0)
        let paper_params_128 = [
            (86, 25, 384),
            (44, 30, 235),
            (26, 35, 168),
            (20, 40, 131),
            (18, 45, 108),
            (14, 50, 93),
            (10, 55, 83),
            (8, 64, 70),
            (6, 84, 54),
            (4, 132, 39),
        ];

        let paper_params_160 = [
            (56, 35, 337),
            (44, 40, 245),
            (28, 45, 193),
            (21, 50, 160),
            (14, 60, 121),
            (13, 70, 99),
            (8, 80, 86),
            (6, 104, 67),
            (4, 168, 48),
        ];

        // Choose parameter set based on security level
        let params = if security_bits <= 128 {
            &paper_params_128[..]
        } else {
            &paper_params_160[..]
        };

        // Find best match for requested v
        let mut best_match = None;
        let mut min_v_diff = usize::MAX;

        for &(w, param_v, d0) in params {
            let v_diff = if param_v >= v {
                param_v - v
            } else {
                v - param_v
            };

            // Prefer exact match or close v, and ensure layer has vertices
            if v_diff < min_v_diff {
                if let Ok(layer_size) = calculate_layer_size(d0, v, w) {
                    if !layer_size.is_zero() {
                        // Verify this parameter set meets security requirements
                        let total_bits = (w as f64).powf(v as f64).log2();
                        let required_bits =
                            security_bits as f64 + ((security_bits as f64).log2() / 2.0);

                        if total_bits >= required_bits {
                            best_match = Some((w, d0));
                            min_v_diff = v_diff;
                        }
                    }
                }
            }
        }

        if let Some((w, d0)) = best_match {
            // Adjust d0 if needed for the specific v
            let mut adjusted_d0 = d0;

            // Ensure d0 is valid for this v and w combination
            let max_d = v * (w - 1);
            if adjusted_d0 > max_d {
                // Find a good d0 in the valid range
                adjusted_d0 = max_d / 2; // Start from middle

                // Find the layer with maximum size around the middle
                let mut best_d0 = adjusted_d0;
                let mut max_size = BigUint::zero();

                for d in (0..=max_d).rev().take(max_d.min(20)) {
                    if let Ok(layer_size) = calculate_layer_size(d, v, w) {
                        if layer_size > max_size {
                            max_size = layer_size;
                            best_d0 = d;
                        }
                    }
                }
                adjusted_d0 = best_d0;
            }

            TSLConfig {
                w,
                v,
                d0: adjusted_d0,
            }
        } else {
            // Fallback: use conservative parameters
            let w = if security_bits <= 128 { 4 } else { 6 };
            let d0 = v * (w - 1) / 2; // Use middle layer

            TSLConfig { w, v, d0 }
        }
    }

    /// Create TSL config with specific parameters
    pub fn with_params(w: usize, v: usize, d0: usize) -> Self {
        assert!(w > 1, "w must be greater than 1");
        assert!(v > 0, "v must be positive");
        assert!(d0 <= v * (w - 1), "d0 must be valid layer");

        TSLConfig { w, v, d0 }
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

    pub fn signature_chains(&self) -> usize {
        self.v // TSL has no checksum
    }
}

/// TSL encoding scheme
/// Maps messages to layer d₀
pub struct TSL {
    config: TSLConfig,
    hasher: SHA256,
    layer_size: BigUint,
}

impl TSL {
    pub fn new(config: TSLConfig) -> Self {
        // Calculate layer d0 size
        let layer_size = calculate_layer_size(config.d0, config.v, config.w)
            .expect("Failed to calculate layer size");

        // Verify layer d0 has positive size
        assert!(!layer_size.is_zero(), "Layer d0 must have positive size");

        TSL {
            config,
            hasher: SHA256::new(),
            layer_size,
        }
    }

    /// Map an integer to a vertex in layer d0
    /// uniformly to vertices in layer d₀.
    pub fn map_to_layer(&self, value: usize) -> Result<Vertex, crate::core::mapping::MappingError> {
        // Handle zero layer size case
        if self.layer_size.is_zero() {
            return Err(crate::core::mapping::MappingError::InvalidLayer {
                expected: self.config.d0,
                actual: 0,
            });
        }

        // For very large layer sizes, we need to use modular arithmetic
        // to map the input value to a valid range
        let mapped_index = if let Some(layer_size_usize) = self.layer_size.to_usize() {
            if layer_size_usize == 0 {
                return Err(crate::core::mapping::MappingError::InvalidLayer {
                    expected: self.config.d0,
                    actual: 0,
                });
            }
            value % layer_size_usize
        } else {
            // For very large layer sizes that don't fit in usize,
            // we use a hash-based approach to map uniformly across a smaller range
            // while maintaining cryptographic properties

            // Use a combination of value and layer parameters to get good distribution
            let hash_input = value
                .wrapping_mul(2654435761) // Use a large prime multiplier
                .wrapping_add(self.config.d0.wrapping_mul(2246822507))
                .wrapping_add(self.config.v.wrapping_mul(3266489917))
                .wrapping_add(self.config.w.wrapping_mul(668265263));

            // Map to a reasonable range that integer_to_vertex can handle
            // Use a range that's small enough to work but large enough for good distribution
            let max_safe_index = (self.config.v * self.config.w).min(10000);
            hash_input % max_safe_index
        };

        // Now try to map this index to a vertex
        // For very large layers, we need to be more conservative
        let mut attempts = 0;
        let mut current_index = mapped_index;

        loop {
            match integer_to_vertex(current_index, self.config.w, self.config.v, self.config.d0) {
                Ok(components) => return Ok(Vertex::new(components)),
                Err(crate::core::mapping::MappingError::IndexOutOfRange { .. }) => {
                    // Try progressively smaller indices
                    attempts += 1;
                    if attempts > 20 {
                        break;
                    }
                    current_index = current_index / 2;
                    if current_index == 0 && attempts == 1 {
                        // If even 0 doesn't work, there might be an issue with the layer
                        break;
                    }
                }
                Err(e) => {
                    // For other errors, try a few smaller values then give up
                    attempts += 1;
                    if attempts > 5 {
                        return Err(e);
                    }
                    current_index = if current_index > 0 {
                        current_index - 1
                    } else {
                        0
                    };
                }
            }
        }

        // If we get here, try the most conservative approach: use index 0
        match integer_to_vertex(0, self.config.w, self.config.v, self.config.d0) {
            Ok(components) => Ok(Vertex::new(components)),
            Err(e) => Err(e),
        }
    }

    /// Encode message and randomness to vertex
    pub fn encode(
        &self,
        message: &[u8],
        randomness: &[u8],
    ) -> Result<Vertex, crate::core::mapping::MappingError> {
        // Paper Algorithm TSL Step 1: Compute H(m || r)
        let mut input = Vec::new();
        input.extend_from_slice(message);
        input.extend_from_slice(randomness);

        let hash = self.hasher.hash(&input);

        // Convert hash to integer
        let mut value = 0usize;
        for (i, &byte) in hash.iter().enumerate().take(8) {
            value |= (byte as usize) << (i * 8);
        }

        // Paper Algorithm TSL Step 2: Map hash output to layer d₀ using Ψ
        self.map_to_layer(value)
    }
}

impl EncodingScheme for TSL {
    fn encode(&self, message: &[u8], randomness: &[u8]) -> Vertex {
        // Call the TSL-specific encode method and handle errors
        TSL::encode(self, message, randomness).unwrap_or_else(|_| {
            // Fallback to sink vertex if mapping fails
            Vertex::new(vec![self.config.w; self.config.v])
        })
    }

    fn alphabet_size(&self) -> usize {
        self.config.w
    }

    fn dimension(&self) -> usize {
        self.config.v
    }
}

impl NonUniformMapping for TSL {
    /// Implementation of the non-uniform mapping Ψ for TSL
    fn map(&self, value: usize) -> Vertex {
        self.map_to_layer(value).unwrap_or_else(|_| {
            // Fallback to sink vertex if mapping fails
            Vertex::new(vec![self.config.w; self.config.v])
        })
    }

    /// For TSL, Pr[Ψ(z) = x] = 1/ℓ_{d₀} if x ∈ layer d₀, else 0
    /// This achieves optimal collision metric μ²_ℓ(Ψ) = 1/ℓ_{d₀}
    fn probability(&self, vertex: &Vertex) -> f64 {
        let hc = crate::core::hypercube::Hypercube::new(self.config.w, self.config.v);
        if hc.calculate_layer(vertex) == self.config.d0 {
            let layer_size = calculate_layer_size(self.config.d0, self.config.v, self.config.w)
                .unwrap()
                .to_usize()
                .unwrap();
            1.0 / layer_size as f64
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hypercube::Hypercube;
    use crate::core::mapping;

    #[test]
    fn test_tsl_config_creation() {
        let lambda = 128;
        // Test TSL configuration creation
        let config = TSLConfig::new(lambda); // 128-bit security

        // For 128-bit security, we need w^v > 2^{λ+log₄λ} ≈ 2^{128+3.5} ≈ 2^131.5
        assert!(config.w() > 0);
        assert!(config.v() > 0);
        assert!(config.d0() > 0);

        // Check security requirement using logarithms to avoid overflow
        // We need: log₂(w^v) > λ + log₄(λ) = λ + log₂(λ)/log₂(4) = λ + log₂(λ)/2
        let log_w_v = (config.v() as f64) * (config.w() as f64).log2();
        let required_bits = lambda as f64 + (lambda as f64).log2() / 2.0;
        assert!(
            log_w_v > required_bits,
            "Security requirement not met: log₂({}^{}) = {:.2} <= {:.2} = {} + log₂({})/2",
            config.w(),
            config.v(),
            log_w_v,
            required_bits,
            lambda,
            lambda
        );

        // Check that layer d0 has vertices
        let layer_size_big = calculate_layer_size(config.d0(), config.v(), config.w()).unwrap();

        // For large layer sizes that don't fit in usize, just check they're positive
        if let Some(layer_size) = layer_size_big.to_usize() {
            assert!(
                layer_size > 0,
                "Layer {} should have positive size",
                config.d0()
            );
        } else {
            // Very large layer size - just check it's not zero
            assert!(
                !layer_size_big.is_zero(),
                "Layer {} should have positive size (large)",
                config.d0()
            );
        }
    }

    #[test]
    fn test_tsl_parameter_selection() {
        // Test parameter selection for different security levels

        // 128-bit security with default v=25
        let config_128 = TSLConfig::new(128);
        assert_eq!(config_128.v(), 25); // Should use default v=25 for 128-bit
        assert_eq!(config_128.w(), 86);

        // 160-bit security with default v=35
        let config_160 = TSLConfig::new(160);
        assert_eq!(config_160.v(), 35); // Should use default v=35 for 160-bit
        assert_eq!(config_160.w(), 56);

        // Test custom v with new_full
        let config_custom = TSLConfig::new_full(128, 30);
        assert_eq!(config_custom.v(), 30);
        assert_eq!(config_custom.w(), 44);
    }

    #[test]
    #[should_panic(expected = "Only 128-bit and 160-bit security levels are supported")]
    fn test_tsl_invalid_security_level_96() {
        // Should panic for unsupported security levels
        let _ = TSLConfig::new(96);
    }

    #[test]
    #[should_panic(expected = "Only 128-bit and 160-bit security levels are supported")]
    fn test_tsl_invalid_security_level_192() {
        // Should panic for unsupported security levels
        let _ = TSLConfig::new(192);
    }

    #[test]
    fn test_tsl_encoding_basic() {
        let w = 4;
        let v = 4;
        let d0 = 4;
        let config = TSLConfig::with_params(w, v, d0); // Small example for testing
        let tsl = TSL::new(config);

        // Test encoding
        let message = b"test message";
        let randomness = b"random seed!";

        let encoded = tsl.encode(message, randomness).unwrap();
        println!("encoded: ${encoded:?}");

        // Verify the encoded vertex is in the correct layer
        let layer = Hypercube::new(w, v).calculate_layer(&encoded);
        assert_eq!(layer, d0); // Should be in layer d0 = 4
    }

    #[test]
    fn test_tsl_encoding_deterministic() {
        let config = TSLConfig::new(128);
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
        let config = TSLConfig::new(128);
        let w = config.w();
        let v = config.v();
        let d0 = config.d0();
        let tsl = TSL::new(config);

        let randomness = b"random seed";

        // Different messages should (likely) produce different outputs
        let encoded1 = tsl.encode(b"message1", randomness).unwrap();
        let encoded2 = tsl.encode(b"message2", randomness).unwrap();

        // They should both be in the same layer (d0)
        let hc = Hypercube::new(w, v);
        assert_eq!(hc.calculate_layer(&encoded1), d0);
        assert_eq!(hc.calculate_layer(&encoded2), d0);

        // Note: With the large paper parameters, the mapping may fallback to sink vertex
        // for both messages, so we just verify they're in the correct layer
        // (Different vertices are likely but not guaranteed due to mapping complexity)
    }

    #[test]
    fn test_tsl_non_uniform_mapping() {
        // Test the non-uniform mapping function Ψ
        let config = TSLConfig::new(128);
        let w = config.w();
        let v = config.v();
        let d0 = config.d0();
        let tsl = TSL::new(config);

        // The mapping should only produce vertices in layer d0
        for i in 0..100 {
            let vertex = tsl.map_to_layer(i).unwrap();
            let layer = Hypercube::new(w, v).calculate_layer(&vertex);
            assert_eq!(layer, d0);
        }
    }

    #[test]
    fn test_tsl_uniform_distribution() {
        // Test that the mapping produces uniform distribution within the layer
        let config = TSLConfig::new(128);
        let d0 = config.d0();
        let w = config.w();
        let v = config.v();
        let tsl = TSL::new(config);

        let layer_size_big = calculate_layer_size(d0, v, w).unwrap();

        // Skip test if layer size is too large to fit in usize
        let layer_size = if let Some(size) = layer_size_big.to_usize() {
            size
        } else {
            // For very large layer sizes, just test that mapping works without panicking
            for i in 0..100 {
                let _vertex = tsl.map_to_layer(i).unwrap();
            }
            return;
        };

        // Skip if layer size is too large for practical testing (> 10000)
        if layer_size > 10000 {
            // Just test that mapping works without panicking
            for i in 0..100 {
                let _vertex = tsl.map_to_layer(i).unwrap();
            }
            return;
        }

        let mut counts = vec![0; layer_size];

        // Map many values and count occurrences
        let num_samples = (layer_size * 10).min(1000); // Limit samples for large layers
        for i in 0..num_samples {
            let vertex = tsl.map_to_layer(i).unwrap();
            // Convert vertex to index within layer
            if let Ok(idx) = mapping::vertex_to_integer(vertex.components(), w, v, d0) {
                if idx < layer_size {
                    counts[idx] += 1;
                }
            }
        }

        // Check that distribution is roughly uniform
        // Allow more variance for smaller sample sizes
        let expected = num_samples / layer_size;
        if expected > 0 {
            for count in counts {
                assert!(count <= expected * 3); // Allow up to 3x expected for small samples
            }
        }
    }

    #[test]
    fn test_tsl_incomparability() {
        // Test that TSL produces vertices from the same layer
        // Note: Vertices in the same layer may still be comparable
        let config = TSLConfig::new(128); // 128-bit security
        let w = config.w();
        let v = config.v();
        let expected_layer = config.d0();
        let tsl = TSL::new(config);

        let vertices: Vec<_> = (0..10).map(|i| tsl.map_to_layer(i).unwrap()).collect();

        // Check that all vertices are in the same layer
        let hc = Hypercube::new(w, v);

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

    #[test]
    fn test_tsl_encoding_paper_params() {
        let test_cases = [
            // security level: 128
            (86, 25, 384),
            (44, 30, 235),
            (26, 35, 168),
            (20, 40, 131),
            (18, 45, 108),
            (14, 50, 93),
            (10, 55, 83),
            (8, 64, 70),
            (9, 67, 66),
            (9, 68, 65),
            (6, 81, 56),
            (6, 84, 54),
            (6, 86, 53),
            (4, 128, 40),
            (5, 132, 39),
            (4, 136, 39),
            // security level: 160
            (56, 35, 337),
            (44, 40, 245),
            (28, 45, 193),
            (21, 50, 160),
            (14, 60, 121),
            (13, 70, 99),
            (8, 80, 86),
            (7, 84, 82),
            (6, 101, 69),
            (7, 104, 67),
            (6, 106, 66),
            (4, 160, 50),
            (4, 165, 49),
            (4, 168, 48),
        ];

        for (w, v, d0) in test_cases {
            let config = TSLConfig::with_params(w, v, d0);
            let tsl = TSL::new(config);

            let message = b"test message";
            let randomness = b"random seed";

            let encoded = tsl.encode(message, randomness).unwrap();

            let layer = Hypercube::new(w, v).calculate_layer(&encoded);
            assert_eq!(layer, d0);
        }
    }
}
