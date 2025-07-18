use hypercube_signatures::core::mapping::{vertex_to_integer, integer_to_vertex, MapToVertex, MapToInteger};

#[test]
fn test_vertex_to_integer_basic() {
    // Test basic vertex to integer mapping
    // For a simple case, verify the mapping is injective
    
    // Binary hypercube [2]^3, layer 1
    // Vertices: (1,2,2), (2,1,2), (2,2,1)
    let v1 = vec![1, 2, 2];
    let v2 = vec![2, 1, 2];
    let v3 = vec![2, 2, 1];
    
    let i1 = vertex_to_integer(&v1, 2, 3, 1);
    let i2 = vertex_to_integer(&v2, 2, 3, 1);
    let i3 = vertex_to_integer(&v3, 2, 3, 1);
    
    // All should map to different integers in [0, 2]
    assert!(i1 < 3);
    assert!(i2 < 3);
    assert!(i3 < 3);
    assert_ne!(i1, i2);
    assert_ne!(i1, i3);
    assert_ne!(i2, i3);
}

#[test]
fn test_integer_to_vertex_basic() {
    // Test integer to vertex mapping
    // For layer d, integers [0, ℓ_d - 1] should map to valid vertices
    
    // Binary hypercube [2]^3, layer 1 (size 3)
    for i in 0..3 {
        let vertex = integer_to_vertex(i, 2, 3, 1);
        
        // Check it's a valid vertex
        assert_eq!(vertex.len(), 3);
        for &x in &vertex {
            assert!(x >= 1 && x <= 2);
        }
        
        // Check it's in the correct layer
        let layer = 3 * 2 - vertex.iter().sum::<usize>();
        assert_eq!(layer, 1);
    }
}

#[test]
fn test_mapping_bijection() {
    // Test that vertex_to_integer and integer_to_vertex are inverses
    
    // Test for various hypercube parameters
    let test_cases = vec![
        (2, 3, 1), // [2]^3, layer 1
        (3, 2, 2), // [3]^2, layer 2
        (4, 4, 5), // [4]^4, layer 5
    ];
    
    for (w, v, d) in test_cases {
        // Only test if layer is valid (d <= v(w-1))
        if d <= v * (w - 1) {
            // Get layer size (this assumes calculate_layer_size is implemented)
            let layer_size = hypercube_signatures::core::layer::calculate_layer_size(d, v, w);
            
            // Test round-trip for several integers
            for i in 0..layer_size.min(10) {
                let vertex = integer_to_vertex(i, w, v, d);
                let i_back = vertex_to_integer(&vertex, w, v, d);
                assert_eq!(i, i_back, "Round trip failed for i={}, w={}, v={}, d={}", i, w, v, d);
            }
        }
    }
}

#[test]
fn test_map_to_vertex_trait() {
    // Test the MapToVertex trait implementation
    let mapper = MapToVertex::new(4, 3, 2);
    
    // Map integer 0 to a vertex in layer 2
    let vertex = mapper.map(0);
    
    // Verify it's in the correct layer
    let layer = 3 * 4 - vertex.iter().sum::<usize>();
    assert_eq!(layer, 2);
}

#[test]
fn test_map_to_integer_trait() {
    // Test the MapToInteger trait implementation
    let mapper = MapToInteger::new(4, 3, 2);
    
    // Create a vertex in layer 2
    let vertex = vec![3, 3, 4]; // layer = 12 - 10 = 2
    let integer = mapper.map(&vertex);
    
    // Verify the integer is in valid range
    let layer_size = hypercube_signatures::core::layer::calculate_layer_size(2, 3, 4);
    assert!(integer < layer_size);
}

#[test]
fn test_mapping_consistency() {
    // Test that all vertices in a layer map to unique integers
    let w = 3;
    let v = 3;
    let d = 3;
    
    // Generate all vertices in layer d
    let mut vertices: Vec<Vec<usize>> = Vec::new();
    // This is a simplified approach - in practice we'd use the iterator
    // For now, we'll test that the mapping is consistent
    
    let layer_size = hypercube_signatures::core::layer::calculate_layer_size(d, v, w);
    let mut mapped_integers = std::collections::HashSet::new();
    
    for i in 0..layer_size {
        let vertex = integer_to_vertex(i, w, v, d);
        let mapped = vertex_to_integer(&vertex, w, v, d);
        assert_eq!(i, mapped);
        mapped_integers.insert(mapped);
    }
    
    // All integers should be unique
    assert_eq!(mapped_integers.len(), layer_size);
}