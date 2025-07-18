// TLFC (Top Layers with Full Checksum) implementation

use crate::core::hypercube::{Hypercube, Vertex};
use crate::core::layer::calculate_layer_size;
use crate::core::mapping::integer_to_vertex;
use crate::crypto::hash::{HashFunction, SHA256};
use crate::core::encoding::{EncodingScheme, NonUniformMapping};

/// TLFC configuration parameters
#[derive(Debug, Clone)]
pub struct TLFCConfig {
    w: usize,
    v: usize,
    d0: usize,
    c: usize, // Number of checksum chains
}

impl TLFCConfig {
    /// Create TLFC config for given security level
    pub fn new(security_bits: usize) -> Self {
        // For TLFC, we need ℓ_{[0:d0]} ≥ 2^λ and c checksum chains
        // Try different parameter combinations
        let candidates = vec![
            (16, 16, 4),  // w=16, v=16, c=4
            (32, 12, 3),  // w=32, v=12, c=3
            (64, 8, 2),   // w=64, v=8, c=2
        ];
        
        for (w, v, c) in candidates {
            // Find appropriate d0 such that sum of layer sizes ≥ 2^λ
            for d0 in 1..=(v * (w - 1)) {
                let total_size: usize = (0..=d0)
                    .map(|d| calculate_layer_size(d, v, w))
                    .sum();
                
                if total_size > 0 && (total_size as f64).log2() >= security_bits as f64 {
                    return TLFCConfig { w, v, d0, c };
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
pub struct TLFC {
    config: TLFCConfig,
    hasher: SHA256,
    total_layer_size: usize,
}

impl TLFC {
    pub fn new(config: TLFCConfig) -> Self {
        // Calculate total size of layers [0, d0]
        let total_layer_size: usize = (0..=config.d0)
            .map(|d| calculate_layer_size(d, config.v, config.w))
            .sum();
        
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
    pub fn calculate_full_checksum(&self, components: &[usize]) -> Vec<usize> {
        let w = self.config.w;
        let c = self.config.c;
        let mut checksums = vec![0; c];
        
        // C_i = Σ_j 2^(j mod c) * (w - a_j) for j where j mod c = i
        for (j, &a_j) in components.iter().enumerate() {
            let i = j % c;
            checksums[i] += (1 << (j % c)) * (w - a_j);
        }
        
        // Normalize to [1, w] range
        for checksum in &mut checksums {
            *checksum = (*checksum % w) + 1;
        }
        
        checksums
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
                let components = integer_to_vertex(
                    layer_index,
                    self.config.w,
                    self.config.v,
                    d
                ).unwrap_or_else(|_| vec![self.config.w; self.config.v]);
                return Vertex::new(components);
            }
            cumulative += layer_size;
        }
        
        // Should not reach here
        panic!("Index out of range");
    }
    
    /// Convert message to WOTS digest including checksums
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