// Hypercube structure and operations

pub struct Hypercube {
    w: usize, // alphabet size
    v: usize, // dimension
}

pub struct Vertex {
    components: Vec<usize>,
}

impl Hypercube {
    pub fn new(w: usize, v: usize) -> Self {
        unimplemented!("Hypercube::new")
    }

    pub fn alphabet_size(&self) -> usize {
        unimplemented!("Hypercube::alphabet_size")
    }

    pub fn dimension(&self) -> usize {
        unimplemented!("Hypercube::dimension")
    }

    pub fn total_vertices(&self) -> usize {
        unimplemented!("Hypercube::total_vertices")
    }

    pub fn is_valid_vertex(&self, vertex: &Vertex) -> bool {
        unimplemented!("Hypercube::is_valid_vertex")
    }

    pub fn sink_vertex(&self) -> Vertex {
        unimplemented!("Hypercube::sink_vertex")
    }

    pub fn calculate_layer(&self, vertex: &Vertex) -> usize {
        unimplemented!("Hypercube::calculate_layer")
    }

    pub fn vertices_in_layer(&self, layer: usize) -> impl Iterator<Item = Vertex> {
        std::iter::empty()
    }

    pub fn distance_from_sink(&self, vertex: &Vertex) -> usize {
        unimplemented!("Hypercube::distance_from_sink")
    }
}

impl Vertex {
    pub fn new(components: Vec<usize>) -> Self {
        unimplemented!("Vertex::new")
    }

    pub fn dimension(&self) -> usize {
        unimplemented!("Vertex::dimension")
    }

    pub fn components(&self) -> &Vec<usize> {
        unimplemented!("Vertex::components")
    }

    pub fn le(&self, other: &Self) -> bool {
        unimplemented!("Vertex::le")
    }
}