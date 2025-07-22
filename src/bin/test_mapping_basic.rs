// Paper-compliant mapping implementation test

use hypercube_signatures::core::mapping::{
    integer_to_vertex, vertex_to_integer, NonUniformMappingPsi,
};

fn main() {
    println!("Testing paper-compliant mapping implementation...");
    println!("Based on 'At the Top of the Hypercube' Section 6.1");

    // Test case: Binary hypercube [2]^3, layer 1
    let w = 2;
    let v = 3;
    let d = 1;

    println!("\nTesting hypercube [{}]^{}, layer {}", w, v, d);

    // Test vertices that should be in layer 1
    let vertices = vec![
        vec![1, 2, 2], // sum = 5, layer = 6 - 5 = 1
        vec![2, 1, 2], // sum = 5, layer = 6 - 5 = 1
        vec![2, 2, 1], // sum = 5, layer = 6 - 5 = 1
    ];

    println!("\n=== Testing paper-exact vertex-to-integer mapping ===");
    for (_i, vertex) in vertices.iter().enumerate() {
        println!("Testing vertex {:?}", vertex);

        // Check layer calculation
        let layer = v * w - vertex.iter().sum::<usize>();
        println!("  Layer: {}", layer);

        if layer == d {
            match vertex_to_integer(vertex, w, v, d) {
                Ok(integer) => {
                    println!("  Vertex to integer: {}", integer);

                    // Test inverse mapping
                    match integer_to_vertex(integer, w, v, d) {
                        Ok(recovered_vertex) => {
                            println!("  Integer to vertex: {:?}", recovered_vertex);
                            if recovered_vertex == *vertex {
                                println!("  ✓ Round-trip successful (paper-compliant)");
                            } else {
                                println!("  ✗ Round-trip failed - implementation error");
                            }
                        }
                        Err(e) => println!("  ✗ Integer to vertex failed: {:?}", e),
                    }
                }
                Err(e) => println!("  ✗ Vertex to integer failed: {:?}", e),
            }
        } else {
            println!("  ✗ Vertex is not in layer {}", d);
        }

        println!();
    }

    // Test integer to vertex for all valid indices using paper-exact formula
    println!("=== Testing paper-exact integer-to-vertex mapping ===");
    match integer_to_vertex(0, w, v, d) {
        Ok(vertex) => {
            let layer = v * w - vertex.iter().sum::<usize>();
            println!("Layer size calculation using paper formula");
            if layer == d {
                println!("  Index 0: {:?} ✓", vertex);
            } else {
                println!("  Index 0: {:?} ✗ (wrong layer: {})", vertex, layer);
            }
        }
        Err(e) => println!("  Index 0: Error {:?}", e),
    }

    // Test non-uniform mapping function Ψ
    println!("\n=== Testing non-uniform mapping function Ψ ===");
    match NonUniformMappingPsi::new(w, v, d) {
        Ok(psi) => {
            println!("Created non-uniform mapping Ψ for layer {}", d);
            println!("Layer size: {}", psi.layer_size());

            // Test mapping some values
            for value in 0..5 {
                match psi.map(value) {
                    Ok(vertex) => match psi.probability(&vertex) {
                        Ok(prob) => {
                            println!("  Value {} → {:?} (prob: {:.4})", value, vertex, prob);
                        }
                        Err(e) => {
                            println!("  Value {} → {:?} (prob error: {:?})", value, vertex, e)
                        }
                    },
                    Err(e) => println!("  Value {} → Error: {:?}", value, e),
                }
            }
        }
        Err(e) => println!("Failed to create non-uniform mapping: {:?}", e),
    }

    // Test with larger hypercube
    println!("\n=== Testing larger hypercube [3]^2, layer 2 ===");
    let w2 = 3;
    let v2 = 2;
    let d2 = 2;

    match NonUniformMappingPsi::new(w2, v2, d2) {
        Ok(psi) => {
            println!(
                "Layer size for [{}]^{}, layer {}: {}",
                w2,
                v2,
                d2,
                psi.layer_size()
            );

            // Test all vertices in this layer
            for i in 0..psi.layer_size() {
                match integer_to_vertex(i, w2, v2, d2) {
                    Ok(vertex) => {
                        let layer = v2 * w2 - vertex.iter().sum::<usize>();
                        if layer == d2 {
                            println!("  Index {}: {:?} ✓", i, vertex);
                        } else {
                            println!("  Index {}: {:?} ✗ (wrong layer: {})", i, vertex, layer);
                        }
                    }
                    Err(e) => println!("  Index {}: Error {:?}", i, e),
                }
            }
        }
        Err(e) => println!("Failed to create mapping for larger hypercube: {:?}", e),
    }

    println!("\n=== Paper compliance verification complete ===");
}
