// Hypercube structure and operations

/// Represents a hypercube [w]^v
#[derive(Debug, Clone,)]
pub struct Hypercube {
    w: usize, // alphabet size [w] = {1, 2, ..., w}
    v: usize, // dimension
}

/// Represents a vertex in the hypercube
#[derive(Debug, Clone, PartialEq, Eq,)]
pub struct Vertex {
    components: Vec<usize,>,
}

impl Hypercube {
    /// Creates a new hypercube [w]^v
    pub fn new(w: usize, v: usize,) -> Self {
        assert!(w > 0, "Alphabet size must be positive");
        assert!(v > 0, "Dimension must be positive");
        Hypercube { w, v, }
    }

    /// Returns the alphabet size w
    pub fn alphabet_size(&self,) -> usize {
        self.w
    }

    /// Returns the dimension v
    pub fn dimension(&self,) -> usize {
        self.v
    }

    /// Returns the total number of vertices w^v
    pub fn total_vertices(&self,) -> usize {
        self.w.pow(self.v as u32,)
    }

    /// Checks if a vertex is valid (all components in [1, w])
    pub fn is_valid_vertex(&self, vertex: &Vertex,) -> bool {
        vertex.components.len() == self.v
            && vertex.components.iter().all(|&x| x >= 1 && x <= self.w,)
    }

    /// Returns the sink vertex (w, w, ..., w)
    pub fn sink_vertex(&self,) -> Vertex {
        Vertex::new(vec![self.w; self.v],)
    }

    /// Calculates the layer of a vertex: d = vw - Σx_i
    pub fn calculate_layer(&self, vertex: &Vertex,) -> usize {
        let sum: usize = vertex.components.iter().sum();
        self.v * self.w - sum
    }

    /// Returns an iterator over all vertices in a given layer
    pub fn vertices_in_layer(&self, layer: usize,) -> impl Iterator<Item = Vertex,> {
        // For now, we'll use a simple but inefficient approach
        // In production, we'd use the mapping functions
        let w = self.w;
        let v = self.v;

        AllVertices::new(w, v,).filter(move |vertex| {
            let sum: usize = vertex.components.iter().sum();
            v * w - sum == layer
        },)
    }

    /// Calculates the distance from a vertex to the sink
    pub fn distance_from_sink(&self, vertex: &Vertex,) -> usize {
        vertex.components.iter().map(|&x| self.w - x,).sum()
    }
}

impl Vertex {
    /// Creates a new vertex with the given components
    pub fn new(components: Vec<usize,>,) -> Self {
        Vertex { components, }
    }

    /// Returns the dimension of the vertex
    pub fn dimension(&self,) -> usize {
        self.components.len()
    }

    /// Returns the components of the vertex
    pub fn components(&self,) -> &Vec<usize,> {
        &self.components
    }

    /// Checks if this vertex is less than or equal to another (component-wise)
    pub fn le(&self, other: &Self,) -> bool {
        self.components.len() == other.components.len()
            && self.components.iter().zip(other.components.iter(),).all(|(&x, &y,)| x <= y,)
    }
}

/// Iterator over all vertices in a hypercube
struct AllVertices {
    w: usize,
    v: usize,
    current: Vec<usize,>,
    finished: bool,
}

impl AllVertices {
    fn new(w: usize, v: usize,) -> Self {
        AllVertices { w, v, current: vec![1; v], finished: false, }
    }
}

impl Iterator for AllVertices {
    type Item = Vertex;

    fn next(&mut self,) -> Option<Self::Item,> {
        if self.finished {
            return None;
        }

        let result = Vertex::new(self.current.clone(),);

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

        Some(result,)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypercube_creation() {
        // Test creating a hypercube [w]^v
        let hc = Hypercube::new(4, 3); // [4]^3
        assert_eq!(hc.alphabet_size(), 4);
        assert_eq!(hc.dimension(), 3);
        assert_eq!(hc.total_vertices(), 64); // 4^3 = 64
    }

    #[test]
    fn test_vertex_creation() {
        // Test vertex creation and validation
        let vertex = Vertex::new(vec![1, 2, 3, 4]);
        assert_eq!(vertex.dimension(), 4);
        assert_eq!(vertex.components(), &vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_vertex_validation() {
        let hc = Hypercube::new(4, 3);
        
        // Valid vertex
        assert!(hc.is_valid_vertex(&Vertex::new(vec![1, 2, 3])));
        assert!(hc.is_valid_vertex(&Vertex::new(vec![4, 4, 4])));
        
        // Invalid vertices
        assert!(!hc.is_valid_vertex(&Vertex::new(vec![0, 2, 3]))); // 0 not in [1,4]
        assert!(!hc.is_valid_vertex(&Vertex::new(vec![1, 2, 5]))); // 5 > 4
        assert!(!hc.is_valid_vertex(&Vertex::new(vec![1, 2]))); // wrong dimension
        assert!(!hc.is_valid_vertex(&Vertex::new(vec![1, 2, 3, 4]))); // wrong dimension
    }

    #[test]
    fn test_sink_vertex() {
        let hc = Hypercube::new(4, 3);
        let sink = hc.sink_vertex();
        
        assert_eq!(sink.components(), &vec![4, 4, 4]);
        assert_eq!(hc.calculate_layer(&sink), 0);
    }

    #[test]
    fn test_vertex_comparison() {
        // Test the partial order on vertices
        let v1 = Vertex::new(vec![1, 2, 3]);
        let v2 = Vertex::new(vec![2, 3, 4]);
        let v3 = Vertex::new(vec![1, 3, 2]);
        
        // v1 <= v2 (component-wise)
        assert!(v1.le(&v2));
        assert!(!v2.le(&v1));
        
        // v1 and v3 are incomparable
        assert!(!v1.le(&v3));
        assert!(!v3.le(&v1));
    }

    #[test]
    fn test_layer_membership() {
        let hc = Hypercube::new(4, 3);
        
        // Sink vertex is in layer 0
        let sink = Vertex::new(vec![4, 4, 4]);
        assert_eq!(hc.calculate_layer(&sink), 0);
        
        // Vertices at distance 1
        let v1 = Vertex::new(vec![3, 4, 4]);
        assert_eq!(hc.calculate_layer(&v1), 1);
        
        // Source vertex (1,1,1) is at maximum distance
        let source = Vertex::new(vec![1, 1, 1]);
        let max_layer = 3 * (4 - 1); // v * (w - 1)
        assert_eq!(hc.calculate_layer(&source), max_layer);
    }

    #[test]
    fn test_hypercube_iteration() {
        // Test that we can iterate over all vertices in a layer
        let hc = Hypercube::new(2, 3); // Binary hypercube
        
        // Layer 0 should have exactly 1 vertex: (2,2,2)
        let layer_0_vertices: Vec<_> = hc.vertices_in_layer(0).collect();
        assert_eq!(layer_0_vertices.len(), 1);
        assert_eq!(layer_0_vertices[0].components(), &vec![2, 2, 2]);
        
        // Layer 1 should have 3 vertices
        let layer_1_vertices: Vec<_> = hc.vertices_in_layer(1).collect();
        assert_eq!(layer_1_vertices.len(), 3);
    }

    #[test]
    fn test_distance_from_sink() {
        let hc = Hypercube::new(4, 3);
        let sink = hc.sink_vertex();
        
        // Distance from sink to itself is 0
        assert_eq!(hc.distance_from_sink(&sink), 0);
        
        // Distance is sum of (w - x_i)
        let v = Vertex::new(vec![2, 3, 4]);
        assert_eq!(hc.distance_from_sink(&v), (4-2) + (4-3) + (4-4)); // 2 + 1 + 0 = 3
    }
}
