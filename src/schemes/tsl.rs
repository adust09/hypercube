// TSL (Top Single Layer) implementation

use crate::core::hypercube::Vertex;
use crate::core::encoding::{EncodingScheme, NonUniformMapping};
use crate::core::layer::calculate_layer_size;
use crate::core::mapping::integer_to_vertex;
use crate::crypto::hash::{HashFunction, SHA256};

/// TSL configuration parameters
#[derive(Debug, Clone)]
pub struct TSLConfig {
    w: usize,
    v: usize,
    d0: usize,
}

impl TSLConfig {
    /// Create TSL config for given security level
    pub fn new(security_bits: usize) -> Self {
        // For TSL, we need w^v > 2^{λ + log₄(λ)}
        // This is approximately 2^{λ + log₂(λ)/2}
        
        let extra_bits = ((security_bits as f64).log2() / 2.0).ceil() as usize;
        let required_bits = security_bits + extra_bits;
        
        // Try different parameter combinations
        // Note: We use smaller values than the paper due to implementation constraints
        let candidates = vec![
            (8, 32),  // w=8, v=32 (reduced from paper)
            (6, 42),  // w=6, v=42
            (4, 64),  // w=4, v=64
        ];
        
        for (w, v) in candidates {
            // Find appropriate d0
            for d in 0..=(v * (w - 1)) {
                let layer_size = calculate_layer_size(d, v, w);
                // Check if layer has enough vertices
                if layer_size > 0 && (layer_size as f64).log2() >= security_bits as f64 {
                    // Additional check for TSL security requirement
                    let total_bits = (w as f64).powf(v as f64).log2();
                    if total_bits >= required_bits as f64 {
                        return TSLConfig { w, v, d0: d };
                    }
                }
            }
        }
        
        // Fallback parameters - use conservative values
        TSLConfig {
            w: 8,
            v: 32,
            d0: 32, // Use a safer value that's guaranteed to have vertices
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
pub struct TSL {
    config: TSLConfig,
    hasher: SHA256,
}

impl TSL {
    pub fn new(config: TSLConfig) -> Self {
        // Verify layer d0 has sufficient size
        let layer_size = calculate_layer_size(config.d0, config.v, config.w);
        assert!(layer_size > 0, "Layer d0 must have positive size");
        
        TSL {
            config,
            hasher: SHA256::new(),
        }
    }
    
    /// Map an integer to a vertex in layer d0
    pub fn map_to_layer(&self, value: usize) -> Vertex {
        let layer_size = calculate_layer_size(self.config.d0, self.config.v, self.config.w);
        let index = value % layer_size;
        
        let components = integer_to_vertex(
            index,
            self.config.w,
            self.config.v,
            self.config.d0
        );
        
        Vertex::new(components)
    }
    
    /// Encode message and randomness to vertex
    pub fn encode(&self, message: &[u8], randomness: &[u8]) -> Vertex {
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
        
        // Map to layer d0
        self.map_to_layer(value)
    }
}

impl EncodingScheme for TSL {
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

impl NonUniformMapping for TSL {
    fn map(&self, value: usize) -> Vertex {
        self.map_to_layer(value)
    }
    
    fn probability(&self, vertex: &Vertex) -> f64 {
        let hc = crate::core::hypercube::Hypercube::new(self.config.w, self.config.v);
        if hc.calculate_layer(vertex) == self.config.d0 {
            let layer_size = calculate_layer_size(self.config.d0, self.config.v, self.config.w);
            1.0 / layer_size as f64
        } else {
            0.0
        }
    }
}