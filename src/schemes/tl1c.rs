// TL1C (Top Layers with 1-Chain Checksum) implementation

use crate::core::encoding::{EncodingScheme, NonUniformMapping};
use crate::core::hypercube::{Hypercube, Vertex};
use crate::core::layer::calculate_layer_size;
use crate::core::mapping::integer_to_vertex;
use crate::crypto::hash::{HashFunction, SHA256};

/// TL1C configuration parameters
#[derive(Debug, Clone)]
pub struct TL1CConfig {
    w: usize,
    v: usize,
    d0: usize,
}

impl TL1CConfig {
    /// Create TL1C config for given security level
    pub fn new(security_bits: usize) -> Self {
        // For TL1C, we need ℓ_{[0:d0]} ≥ 2^λ
        // Try different parameter combinations
        // Note: w must be large enough to accommodate checksum d0+1
        let candidates = vec![
            (16, 16), // w=16, v=16
            (32, 12), // w=32, v=12
            (64, 8),  // w=64, v=8
        ];

        for (w, v) in candidates {
            // Find appropriate d0 such that sum of layer sizes ≥ 2^λ
            for d0 in 1..=(v * (w - 1)) {
                let total_size: usize = (0..=d0).map(|d| calculate_layer_size(d, v, w)).sum();

                if total_size > 0 && (total_size as f64).log2() >= security_bits as f64 {
                    // Also check checksum fits in alphabet
                    if d0 + 1 <= w {
                        return TL1CConfig { w, v, d0 };
                    }
                }
            }
        }

        // Fallback - use larger w to accommodate checksum
        TL1CConfig { w: 16, v: 32, d0: 10 }
    }

    /// Create TL1C config with specific parameters
    pub fn with_params(w: usize, v: usize, d0: usize) -> Self {
        assert!(w > 1, "w must be greater than 1");
        assert!(v > 0, "v must be positive");
        assert!(d0 <= v * (w - 1), "d0 must be valid layer");
        assert!(d0 + 1 <= w, "Checksum d0+1 must fit in alphabet [1,w]");

        TL1CConfig { w, v, d0 }
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
    pub fn new(config: TL1CConfig) -> Self {
        // Calculate total size of layers [0, d0]
        let total_layer_size: usize =
            (0..=config.d0).map(|d| calculate_layer_size(d, config.v, config.w)).sum();

        assert!(total_layer_size > 0, "Total layer size must be positive");

        TL1C { config, hasher: SHA256::new(), total_layer_size }
    }

    /// Encode message with 1-chain checksum
    pub fn encode_with_checksum(&self, message: &[u8], randomness: &[u8]) -> (Vertex, usize) {
        let vertex = self.encode(message, randomness);
        let hc = Hypercube::new(self.config.w, self.config.v);
        let layer = hc.calculate_layer(&vertex);
        let checksum = self.calculate_checksum(layer);
        (vertex, checksum)
    }

    /// Calculate checksum for a layer
    pub fn calculate_checksum(&self, layer: usize) -> usize {
        // Checksum is layer + 1
        layer + 1
    }

    /// Map to top layers [0, d0]
    pub fn map_to_top_layers(&self, value: usize) -> Vertex {
        // Map uniformly to layers [0, d0]
        let index = value % self.total_layer_size;

        // Find which layer this index falls into
        let mut cumulative = 0;
        for d in 0..=self.config.d0 {
            let layer_size = calculate_layer_size(d, self.config.v, self.config.w);
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

    /// Convert message to WOTS digest including checksum
    pub fn message_to_wots_digest(&self, message: &[u8], randomness: &[u8]) -> Vec<usize> {
        let (vertex, checksum) = self.encode_with_checksum(message, randomness);

        let mut digest = vertex.components().clone();
        digest.push(checksum);

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

impl EncodingScheme for TL1C {
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

impl NonUniformMapping for TL1C {
    fn map(&self, value: usize) -> Vertex {
        self.map_to_top_layers(value)
    }

    fn probability(&self, vertex: &Vertex) -> f64 {
        let hc = Hypercube::new(self.config.w, self.config.v);
        let layer = hc.calculate_layer(vertex);

        if layer <= self.config.d0 {
            // Uniform within top layers
            1.0 / self.total_layer_size as f64
        } else {
            0.0
        }
    }
}
