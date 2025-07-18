// Encoding schemes and traits

use crate::core::hypercube::Vertex;

/// Trait for encoding schemes that map messages to hypercube vertices
pub trait EncodingScheme {
    /// Encode a message with randomness to a vertex
    fn encode(&self, message: &[u8], randomness: &[u8]) -> Vertex;
    
    /// Get the alphabet size w
    fn alphabet_size(&self) -> usize;
    
    /// Get the dimension v
    fn dimension(&self) -> usize;
}

/// Trait for non-uniform mapping functions
pub trait NonUniformMapping {
    /// Map an integer to a vertex according to the distribution
    fn map(&self, value: usize) -> Vertex;
    
    /// Get the probability of mapping to a specific vertex
    fn probability(&self, vertex: &Vertex) -> f64;
}

/// Calculate the collision metric μ_ℓ²(f)
pub fn calculate_collision_metric(
    mapping: &dyn NonUniformMapping,
    v: usize,
    w: usize
) -> f64 {
    use crate::core::hypercube::{Hypercube, Vertex};
    
    let hc = Hypercube::new(w, v);
    let mut sum = 0.0;
    
    // Sum over all vertices in the hypercube
    // This is a simplified implementation for small hypercubes
    // In practice, we'd use more efficient methods
    for vertex in AllVertices::new(w, v).take(1000) { // Limit for testing
        let p = mapping.probability(&vertex);
        sum += p * p;
    }
    
    sum
}

// Helper iterator for all vertices
struct AllVertices {
    w: usize,
    v: usize,
    current: Vec<usize>,
    finished: bool,
}

impl AllVertices {
    fn new(w: usize, v: usize) -> Self {
        AllVertices {
            w,
            v,
            current: vec![1; v],
            finished: v == 0,
        }
    }
}

impl Iterator for AllVertices {
    type Item = Vertex;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let result = Vertex::new(self.current.clone());

        // Increment to next vertex
        let mut carry = true;
        for i in (0..self.v).rev() {
            if carry {
                if self.current[i] < self.w {
                    self.current[i] += 1;
                    carry = false;
                } else {
                    self.current[i] = 1;
                }
            }
        }

        if carry {
            self.finished = true;
        }

        Some(result)
    }
}