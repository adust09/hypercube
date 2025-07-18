// Vertex to integer mapping functions

pub fn vertex_to_integer(vertex: &[usize], w: usize, v: usize, d: usize) -> usize {
    unimplemented!("vertex_to_integer")
}

pub fn integer_to_vertex(i: usize, w: usize, v: usize, d: usize) -> Vec<usize> {
    unimplemented!("integer_to_vertex")
}

pub struct MapToVertex {
    w: usize,
    v: usize,
    d: usize,
}

impl MapToVertex {
    pub fn new(w: usize, v: usize, d: usize) -> Self {
        unimplemented!("MapToVertex::new")
    }

    pub fn map(&self, i: usize) -> Vec<usize> {
        unimplemented!("MapToVertex::map")
    }
}

pub struct MapToInteger {
    w: usize,
    v: usize,
    d: usize,
}

impl MapToInteger {
    pub fn new(w: usize, v: usize, d: usize) -> Self {
        unimplemented!("MapToInteger::new")
    }

    pub fn map(&self, vertex: &[usize]) -> usize {
        unimplemented!("MapToInteger::map")
    }
}