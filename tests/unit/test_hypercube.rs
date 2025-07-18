use hypercube_signatures::core::hypercube::{Hypercube, Vertex};

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