use hypercube_signatures::core::encoding::{EncodingScheme, NonUniformMapping};
use hypercube_signatures::core::hypercube::{Hypercube, Vertex};

#[test]
fn test_encoding_trait() {
    // Test the generic encoding trait
    struct TestEncoding {
        w: usize,
        v: usize,
    }
    
    impl EncodingScheme for TestEncoding {
        fn encode(&self, message: &[u8], randomness: &[u8]) -> Vertex {
            // Simple test implementation
            let _ = (message, randomness);
            Vertex::new(vec![self.w; self.v])
        }
        
        fn alphabet_size(&self) -> usize {
            self.w
        }
        
        fn dimension(&self) -> usize {
            self.v
        }
        
        fn name(&self) -> &str {
            "TestEncoding"
        }
    }
    
    let encoding = TestEncoding { w: 4, v: 3 };
    let vertex = encoding.encode(b"test", b"rand");
    assert_eq!(vertex.components(), &vec![4, 4, 4]);
}

#[test]
fn test_non_uniform_mapping_trait() {
    // Test the non-uniform mapping trait
    struct SingleLayerMapping {
        hypercube: Hypercube,
        target_layer: usize,
    }
    
    impl NonUniformMapping for SingleLayerMapping {
        fn map(&self, value: usize) -> Vertex {
            // Map to vertices in target layer
            let layer_size = hypercube_signatures::core::layer::calculate_layer_size(
                self.target_layer, 
                self.hypercube.dimension(), 
                self.hypercube.alphabet_size()
            );
            
            let index = value % layer_size;
            let components = hypercube_signatures::core::mapping::integer_to_vertex(
                index,
                self.hypercube.alphabet_size(),
                self.hypercube.dimension(),
                self.target_layer
            ).unwrap_or_else(|_| vec![self.hypercube.alphabet_size(); self.hypercube.dimension()]);
            Vertex::new(components)
        }
        
        fn probability(&self, vertex: &Vertex) -> f64 {
            // Uniform within target layer, 0 outside
            if self.hypercube.calculate_layer(vertex) == self.target_layer {
                let layer_size = hypercube_signatures::core::layer::calculate_layer_size(
                    self.target_layer,
                    self.hypercube.dimension(),
                    self.hypercube.alphabet_size()
                );
                1.0 / layer_size as f64
            } else {
                0.0
            }
        }
    }
    
    let hc = Hypercube::new(4, 3);
    let mapping = SingleLayerMapping {
        hypercube: hc.clone(),
        target_layer: 5,
    };
    
    // Test mapping produces vertices in correct layer
    for i in 0..20 {
        let vertex = mapping.map(i);
        assert_eq!(hc.calculate_layer(&vertex), 5);
    }
    
    // Test probability function
    let vertex_in_layer = mapping.map(0);
    assert!(mapping.probability(&vertex_in_layer) > 0.0);
    
    let vertex_not_in_layer = Vertex::new(vec![1, 1, 1]);
    assert_eq!(mapping.probability(&vertex_not_in_layer), 0.0);
}

#[test]
fn test_collision_metric() {
    // Test collision metric calculation
    use hypercube_signatures::core::encoding::calculate_collision_metric;
    
    struct UniformMapping {
        size: usize,
    }
    
    impl NonUniformMapping for UniformMapping {
        fn map(&self, value: usize) -> Vertex {
            // Map uniformly to a small set
            let index = value % self.size;
            Vertex::new(vec![index + 1])
        }
        
        fn probability(&self, _vertex: &Vertex) -> f64 {
            1.0 / self.size as f64
        }
    }
    
    let mapping = UniformMapping { size: 4 };
    
    // For uniform distribution on 4 elements:
    // μ_ℓ² = Σ p_i² = 4 * (1/4)² = 4/16 = 1/4
    let metric = calculate_collision_metric(&mapping, 1, 4);
    assert!((metric - 0.25).abs() < 0.001);
}

#[test]
fn test_target_collision_resistance() {
    // Test that encoding provides target collision resistance
    use hypercube_signatures::crypto::hash::{SHA256, HashFunction};
    
    struct HashBasedEncoding {
        hasher: SHA256,
        w: usize,
        v: usize,
    }
    
    impl EncodingScheme for HashBasedEncoding {
        fn encode(&self, message: &[u8], randomness: &[u8]) -> Vertex {
            let mut input = Vec::new();
            input.extend_from_slice(message);
            input.extend_from_slice(randomness);
            
            let hash = self.hasher.hash(&input);
            
            // Simple mapping: use hash bytes to determine vertex
            let mut components = Vec::new();
            for i in 0..self.v {
                let byte = hash[i % hash.len()] as usize;
                components.push((byte % self.w) + 1);
            }
            
            Vertex::new(components)
        }
        
        fn alphabet_size(&self) -> usize {
            self.w
        }
        
        fn dimension(&self) -> usize {
            self.v
        }
        
        fn name(&self) -> &str {
            "HashBasedEncoding"
        }
    }
    
    let encoding = HashBasedEncoding {
        hasher: SHA256::new(),
        w: 4,
        v: 8,
    };
    
    // Different messages with same randomness
    let r = b"randomness";
    let v1 = encoding.encode(b"message1", r);
    let v2 = encoding.encode(b"message2", r);
    assert_ne!(v1.components(), v2.components());
    
    // Same message with different randomness
    let m = b"message";
    let v3 = encoding.encode(m, b"random1");
    let v4 = encoding.encode(m, b"random2");
    assert_ne!(v3.components(), v4.components());
}