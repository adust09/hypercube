// Hypercube structure and operations

/// Represents a hypercube [w]^v
#[derive(Debug, Clone)]
pub struct Hypercube {
    w: usize, // alphabet size [w] = {1, 2, ..., w}
    v: usize, // dimension
}

/// Represents a vertex in the hypercube
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vertex {
    components: Vec<usize>,
}

impl Hypercube {
    /// Creates a new hypercube [w]^v
    pub fn new(w: usize, v: usize) -> Self {
        assert!(w > 0, "Alphabet size must be positive");
        assert!(v > 0, "Dimension must be positive");
        Hypercube { w, v }
    }

    /// Returns the alphabet size w
    pub fn alphabet_size(&self) -> usize {
        self.w
    }

    /// Returns the dimension v
    pub fn dimension(&self) -> usize {
        self.v
    }

    /// Returns the total number of vertices w^v
    pub fn total_vertices(&self) -> usize {
        self.w.pow(self.v as u32)
    }

    /// Checks if a vertex is valid (all components in [1, w])
    pub fn is_valid_vertex(&self, vertex: &Vertex) -> bool {
        vertex.components.len() == self.v
            && vertex.components.iter().all(|&x| x >= 1 && x <= self.w)
    }

    /// Returns the sink vertex (w, w, ..., w)
    pub fn sink_vertex(&self) -> Vertex {
        Vertex::new(vec![self.w; self.v])
    }

    /// Calculates the layer of a vertex: d = vw - Σx_i
    pub fn calculate_layer(&self, vertex: &Vertex) -> usize {
        let sum: usize = vertex.components.iter().sum();
        self.v * self.w - sum
    }

    /// Returns an iterator over all vertices in a given layer
    pub fn vertices_in_layer(&self, layer: usize) -> impl Iterator<Item = Vertex> {
        // For now, we'll use a simple but inefficient approach
        // In production, we'd use the mapping functions
        let w = self.w;
        let v = self.v;
        
        AllVertices::new(w, v)
            .filter(move |vertex| {
                let sum: usize = vertex.components.iter().sum();
                v * w - sum == layer
            })
    }

    /// Calculates the distance from a vertex to the sink
    pub fn distance_from_sink(&self, vertex: &Vertex) -> usize {
        vertex.components.iter()
            .map(|&x| self.w - x)
            .sum()
    }
}

impl Vertex {
    /// Creates a new vertex with the given components
    pub fn new(components: Vec<usize>) -> Self {
        Vertex { components }
    }

    /// Returns the dimension of the vertex
    pub fn dimension(&self) -> usize {
        self.components.len()
    }

    /// Returns the components of the vertex
    pub fn components(&self) -> &Vec<usize> {
        &self.components
    }

    /// Checks if this vertex is less than or equal to another (component-wise)
    pub fn le(&self, other: &Self) -> bool {
        self.components.len() == other.components.len()
            && self.components.iter()
                .zip(other.components.iter())
                .all(|(&x, &y)| x <= y)
    }
}

/// Iterator over all vertices in a hypercube
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
            finished: false,
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