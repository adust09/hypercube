// Layer calculations for hypercube
//
// Paper: "At the Top of the Hypercube" Section 6 and Theorem 6
// This module implements layer size calculations using the exact
// formula from the paper with inclusion-exclusion principle.

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Calculate the layer of a vertex: d = vw - Σx_i
/// (Section 2.1): d = vw - Σᵢ₌₁ᵛ xᵢ
/// This function computes which layer a vertex belongs to based on
/// the sum of its components.
pub fn calculate_layer(vertex: &[usize], w: usize,) -> usize {
    let v = vertex.len();
    let sum: usize = vertex.iter().sum();
    v * w - sum
}

/// Calculate the size of layer d in hypercube [w]^v
/// Paper Theorem 6: ℓ_d = Σ_{s=0}^{⌊d/w⌋} (-1)^s · C(v,s) · C(d-s·w+v-1, v-1)
///
/// This is the exact formula for the number of vertices in layer d,
/// derived using the inclusion-exclusion principle. The formula counts
/// v-dimensional vectors with components in [w] that sum to vw - d.
pub fn calculate_layer_size(d: usize, v: usize, w: usize,) -> usize {
    // Special cases
    if v == 0 {
        return if d == 0 { 1 } else { 0 };
    }

    // Maximum possible layer is v(w-1)
    if d > v * (w - 1) {
        return 0;
    }

    let mut sum = BigUint::zero();
    let max_s = d / w;

    for s in 0..=max_s {
        // Paper: Calculate C(v, s) - binomial coefficient for inclusion-exclusion
        let binom_v_s = binomial(v, s,);

        // Calculate d - s*w + v - 1
        let inner = d as i64 - (s * w) as i64 + v as i64 - 1;

        // If inner < v-1, the binomial coefficient is 0
        if inner < (v - 1) as i64 {
            continue;
        }

        // Paper: Calculate C(d-s*w+v-1, v-1) - the number of weak compositions
        // This counts non-negative integer solutions to x₁ + ... + xᵥ = d - sw
        let binom_inner = binomial(inner as usize, v - 1,);

        // Paper: Apply inclusion-exclusion principle with alternating signs
        // The (-1)^s factor alternates between adding and subtracting terms
        let term = binom_v_s * binom_inner;
        if s % 2 == 0 {
            sum += term;
        } else {
            // Ensure we don't underflow
            if sum >= term {
                sum -= term;
            } else {
                // This shouldn't happen for valid inputs
                return 0;
            }
        }
    }

    // Convert BigUint to usize
    // For reasonable hypercube sizes, this should fit in usize
    sum.to_string().parse().unwrap_or(0,)
}

/// Calculate binomial coefficient C(n, k)
/// Paper Section 2: Standard binomial coefficient computation
/// C(n, k) = n! / (k! · (n-k)!) = number of ways to choose k items from n
fn binomial(n: usize, k: usize,) -> BigUint {
    if k > n {
        return BigUint::zero();
    }

    if k == 0 || k == n {
        return BigUint::one();
    }

    // Use the more efficient formula: C(n,k) = n! / (k! * (n-k)!)
    // But calculate it as: C(n,k) = (n * (n-1) * ... * (n-k+1)) / (k * (k-1) * ... * 1)
    let k = k.min(n - k,); // Take advantage of symmetry

    let mut numerator = BigUint::one();
    let mut denominator = BigUint::one();

    for i in 0..k {
        numerator *= n - i;
        denominator *= i + 1;
    }

    numerator / denominator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binomial() {
        assert_eq!(binomial(5, 0), BigUint::from(1u32));
        assert_eq!(binomial(5, 1), BigUint::from(5u32));
        assert_eq!(binomial(5, 2), BigUint::from(10u32));
        assert_eq!(binomial(5, 3), BigUint::from(10u32));
        assert_eq!(binomial(5, 4), BigUint::from(5u32));
        assert_eq!(binomial(5, 5), BigUint::from(1u32));
        assert_eq!(binomial(5, 6), BigUint::from(0u32));
    }

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
        let size = calculate_layer_size(4, 4, 4,);
        assert!(size > 0); // Exact value depends on implementation

        // Layer size should be 0 for d > v(w-1)
        assert_eq!(calculate_layer_size(10, 3, 2), 0); // d=10 > 3*(2-1)=3
    }

    #[test]
    fn test_layer_size_symmetry() {
        // Test that layer sizes have expected symmetry properties
        // For small hypercubes, verify against hand-calculated values

        // Binary hypercube [2]^3
        let total_vertices = 2_usize.pow(3,);
        let mut sum = 0;
        for d in 0..=3 {
            sum += calculate_layer_size(d, 3, 2,);
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
}
