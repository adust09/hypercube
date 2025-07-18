// Vertex to integer mapping functions

use crate::core::layer::calculate_layer_size;

/// Maps a vertex in layer d to an integer in [0, ℓ_d)
/// This is a simplified implementation for testing
pub fn vertex_to_integer(vertex: &[usize], w: usize, v: usize, d: usize) -> usize {
    // Verify the vertex is in the correct layer
    let layer = v * w - vertex.iter().sum::<usize>();
    assert_eq!(layer, d, "Vertex is not in layer {}", d);
    
    // Simple lexicographic ordering within the layer
    // In production, we'd use the efficient mapping from the paper
    let mut index = 0;
    let mut count = 0;
    
    // Generate all vertices in lexicographic order and count
    for candidate in generate_vertices_in_layer(w, v, d) {
        if candidate == vertex {
            return count;
        }
        count += 1;
    }
    
    panic!("Vertex not found in layer");
}

/// Maps an integer in [0, ℓ_d) to a vertex in layer d
pub fn integer_to_vertex(i: usize, w: usize, v: usize, d: usize) -> Vec<usize> {
    let layer_size = calculate_layer_size(d, v, w);
    assert!(i < layer_size, "Integer {} out of range for layer size {}", i, layer_size);
    
    // Generate vertices in lexicographic order and return the i-th one
    for (idx, vertex) in generate_vertices_in_layer(w, v, d).enumerate() {
        if idx == i {
            return vertex;
        }
    }
    
    panic!("Failed to find vertex at index {}", i);
}

/// Helper function to generate all vertices in a layer in lexicographic order
fn generate_vertices_in_layer(w: usize, v: usize, d: usize) -> impl Iterator<Item = Vec<usize>> {
    // Generate all possible vertices and filter by layer
    CartesianProduct::new(w, v)
        .filter(move |vertex| {
            let sum: usize = vertex.iter().sum();
            v * w - sum == d
        })
}

/// Iterator for Cartesian product [1,w]^v
struct CartesianProduct {
    w: usize,
    v: usize,
    current: Vec<usize>,
    finished: bool,
}

impl CartesianProduct {
    fn new(w: usize, v: usize) -> Self {
        CartesianProduct {
            w,
            v,
            current: vec![1; v],
            finished: v == 0,
        }
    }
}

impl Iterator for CartesianProduct {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let result = self.current.clone();

        // Increment to next vertex in lexicographic order
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

pub struct MapToVertex {
    w: usize,
    v: usize,
    d: usize,
}

impl MapToVertex {
    pub fn new(w: usize, v: usize, d: usize) -> Self {
        MapToVertex { w, v, d }
    }

    pub fn map(&self, i: usize) -> Vec<usize> {
        integer_to_vertex(i, self.w, self.v, self.d)
    }
}

pub struct MapToInteger {
    w: usize,
    v: usize,
    d: usize,
}

impl MapToInteger {
    pub fn new(w: usize, v: usize, d: usize) -> Self {
        MapToInteger { w, v, d }
    }

    pub fn map(&self, vertex: &[usize]) -> usize {
        vertex_to_integer(vertex, self.w, self.v, self.d)
    }
}