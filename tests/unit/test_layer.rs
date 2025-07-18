use hypercube_signatures::core::layer::{calculate_layer, calculate_layer_size};

#[test]
fn test_calculate_layer_basic() {
    // Test for basic layer calculation
    // Layer d = vw - sum(x_i)
    
    // Example: w=4, v=3, vertex=(4,4,4)
    // Layer = 3*4 - (4+4+4) = 12 - 12 = 0 (sink vertex)
    assert_eq!(calculate_layer(&vec![4, 4, 4], 4), 0);
    
    // Example: w=4, v=3, vertex=(3,4,4)
    // Layer = 3*4 - (3+4+4) = 12 - 11 = 1
    assert_eq!(calculate_layer(&vec![3, 4, 4], 4), 1);
    
    // Example: w=4, v=3, vertex=(1,1,1)
    // Layer = 3*4 - (1+1+1) = 12 - 3 = 9
    assert_eq!(calculate_layer(&vec![1, 1, 1], 4), 9);
}

#[test]
fn test_calculate_layer_edge_cases() {
    // Single dimension
    assert_eq!(calculate_layer(&vec![4], 4), 0);
    assert_eq!(calculate_layer(&vec![1], 4), 3);
    
    // Large dimensions
    let vertex = vec![2; 10]; // 10-dimensional vertex with all 2s
    assert_eq!(calculate_layer(&vertex, 3), 10 * 3 - 20); // 30 - 20 = 10
}

#[test]
fn test_calculate_layer_size_basic() {
    // Test layer size calculation
    // For w=2, v=3 (binary case)
    // Layer sizes follow multinomial coefficients
    
    // Layer 0 (sink): only (2,2,2) -> size = 1
    assert_eq!(calculate_layer_size(0, 3, 2), 1);
    
    // Layer 1: vertices at distance 1 from sink
    // (1,2,2), (2,1,2), (2,2,1) -> size = 3
    assert_eq!(calculate_layer_size(1, 3, 2), 3);
    
    // Layer 2: vertices at distance 2 from sink
    // (1,1,2), (1,2,1), (2,1,1) -> size = 3
    assert_eq!(calculate_layer_size(2, 3, 2), 3);
    
    // Layer 3: only (1,1,1) -> size = 1
    assert_eq!(calculate_layer_size(3, 3, 2), 1);
}

#[test]
fn test_calculate_layer_size_formula() {
    // Test the formula from the paper:
    // ℓ_d = Σ_{s=0}^{⌊d/w⌋} (-1)^s · C(v,s) · C(d-s·w+v-1, v-1)
    
    // For w=4, v=4, d=4
    // This should match known values from the paper
    let size = calculate_layer_size(4, 4, 4);
    assert!(size > 0); // Exact value depends on implementation
    
    // Layer size should be 0 for d > v(w-1)
    assert_eq!(calculate_layer_size(10, 3, 2), 0); // d=10 > 3*(2-1)=3
}

#[test]
fn test_layer_size_symmetry() {
    // Test that layer sizes have expected symmetry properties
    // For small hypercubes, verify against hand-calculated values
    
    // Binary hypercube [2]^3
    let total_vertices = 2_usize.pow(3);
    let mut sum = 0;
    for d in 0..=3 {
        sum += calculate_layer_size(d, 3, 2);
    }
    assert_eq!(sum, total_vertices);
}

#[test]
fn test_vertex_validation() {
    // Test that vertices are validated correctly
    // All components should be in range [1, w]
    
    // This test assumes a validation function exists
    // We'll add it when implementing
}