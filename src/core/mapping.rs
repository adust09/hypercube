// Vertex to integer mapping functions - Paper-compliant implementation
// Based on "At the Top of the Hypercube" Section 4.3
//
// This module implements the bijective mappings between vertices in a layer
// and integers [0, ℓ_d), as well as the non-uniform mapping function Ψ.

use num_bigint::BigUint;
use num_traits::{CheckedSub, One, ToPrimitive, Zero};

/// Maps a vertex in layer d to an integer in [0, ℓ_d)
/// Paper Section 4.3: Bijective mapping from layer d vertices to {0, 1, ..., ℓ_d - 1}
/// This is essential for constructing the non-uniform mapping Ψ in the signature schemes.
///
/// For vertex a = (a₁, ..., aᵥ) in layer d, this maps it to an integer
/// in [0, ℓ_d) according to the paper's MapToInteger algorithm.
/// TODO: don't need MapToInteger for sign/verify?
pub fn vertex_to_integer(
    vertex: &[usize],
    w: usize,
    v: usize,
    d: usize,
) -> Result<usize, MappingError> {
    // Verify input vertex is valid
    if vertex.len() != v {
        return Err(MappingError::InvalidLayer {
            expected: d,
            actual: 0,
        });
    }

    // Validate coordinates are in range [1, w]
    for (i, &coord) in vertex.iter().enumerate() {
        if coord < 1 || coord > w {
            return Err(MappingError::InvalidCoordinate {
                position: i,
                value: coord,
                max: w,
            });
        }
    }

    // Initialize x_v := 0 and d_v := w - a_v
    let mut x_v = BigUint::zero();
    let mut d_v = w - vertex[v - 1];

    // Process from v-1 downto 1
    for i in (0..v - 1).rev() {
        // Set j_i := w - a_i
        let j_i = w - vertex[i];

        // Set d_i := d_{i+1} + j_i
        let d_i = d_v + j_i;

        // Calculate the range for the sum
        let remaining_dims = v - i - 1;
        let j_min = if d_i > (w - 1) * remaining_dims {
            d_i - (w - 1) * remaining_dims
        } else {
            0
        };

        // Set x_i := x_{i+1} + sum
        let mut sum = BigUint::zero();
        for j in j_min..j_i {
            let sub_d = d_i - j;
            let sub_v = remaining_dims;
            sum += calculate_layer_size(sub_d, sub_v, w)?;
        }

        x_v = x_v + sum;
        d_v = d_i;
    }

    // Verify the vertex is in the correct layer
    if d_v != d {
        return Err(MappingError::InvalidLayer {
            expected: d,
            actual: d_v,
        });
    }

    // Convert to usize and return
    x_v.to_usize().ok_or(MappingError::IntegerOverflow)
}

/// Calculate layer size using the exact formula from the paper
/// ℓ_d = Σ_{s=0}^{⌊d/w⌋} (-1)^s · C(v,s) · C(d-s·w+v-1, v-1)
/// This is the same formula as in layer.rs but returns BigUint for exact arithmetic
/// in the mapping calculations.
pub fn calculate_layer_size(d: usize, v: usize, w: usize) -> Result<BigUint, MappingError> {
    if v == 0 {
        return Ok(if d == 0 {
            BigUint::one()
        } else {
            BigUint::zero()
        });
    }

    if d > v * (w - 1) {
        return Ok(BigUint::zero());
    }

    let mut sum = BigUint::zero();
    let max_s = d / w;

    for s in 0..=max_s {
        // Calculate C(v, s)
        let binom_v_s = binomial_coefficient(v, s);

        // Calculate d - s*w + v - 1
        let inner_arg = d + v - 1 - s * w;

        // Calculate C(d-s*w+v-1, v-1)
        let binom_inner = if inner_arg >= v - 1 {
            binomial_coefficient(inner_arg, v - 1)
        } else {
            BigUint::zero()
        };

        // Apply inclusion-exclusion principle
        let term = binom_v_s * binom_inner;
        if s % 2 == 0 {
            sum += term;
        } else {
            sum = sum.checked_sub(&term).unwrap_or(BigUint::zero());
        }
    }

    Ok(sum)
}

/// Calculate exact binomial coefficient C(n, k) using the paper's requirements
/// Paper Section 2: Standard binomial coefficient for exact calculations
/// Uses BigUint to avoid overflow in intermediate calculations.
fn binomial_coefficient(n: usize, k: usize) -> BigUint {
    if k > n {
        return BigUint::zero();
    }

    if k == 0 || k == n {
        return BigUint::one();
    }

    // Use symmetry to optimize calculation
    let k = k.min(n - k);

    let mut result = BigUint::one();
    for i in 0..k {
        result = result * (n - i) / (i + 1);
    }

    result
}

// Helper function removed - no longer needed in the current implementation

/// Error types for mapping operations
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum MappingError {
    InvalidLayer {
        expected: usize,
        actual: usize,
    },
    InvalidCoordinate {
        position: usize,
        value: usize,
        max: usize,
    },
    IntegerOverflow,
    IndexOutOfRange {
        index: usize,
        max: usize,
    },
}

/// Maps an integer in [0, ℓ_d) to a vertex in layer d
/// Paper Section 4.3: Inverse of the vertex-to-integer bijection.
/// This allows uniform sampling from layer d by mapping random integers.
///
/// Given an integer x ∈ [0, ℓ_d), this constructs the corresponding vertex
/// in layer d according to the paper's MapToVertex algorithm.
pub fn integer_to_vertex(
    x: usize,
    w: usize,
    v: usize,
    d: usize,
) -> Result<Vec<usize>, MappingError> {
    let layer_size_big = calculate_layer_size(d, v, w)?;

    // For very large layer sizes, accept any reasonable x value
    if let Some(layer_size) = layer_size_big.to_usize() {
        if x >= layer_size {
            return Err(MappingError::IndexOutOfRange {
                index: x,
                max: layer_size,
            });
        }
    }
    // If layer_size is too large to fit in usize, we proceed with the algorithm
    // assuming x is within a reasonable range

    let mut vertex = vec![0; v];
    let mut x_i = x;
    let mut d_i = d;

    // Process each coordinate position from 1 to v-1
    for i in 0..v - 1 {
        let remaining_dims = v - i;

        // Calculate the valid range for j_i
        let j_min = if d_i > (w - 1) * (remaining_dims - 1) {
            d_i - (w - 1) * (remaining_dims - 1)
        } else {
            0
        };
        let j_max = d_i.min(w - 1);

        // Find j_i such that the sum condition is satisfied
        let mut sum_before = BigUint::zero();
        let mut j_i = j_min;

        for j in j_min..=j_max {
            let sub_d = d_i - j;
            let sub_v = remaining_dims - 1;
            let layer_size = calculate_layer_size(sub_d, sub_v, w)?;

            let sum_including = &sum_before + &layer_size;

            if let Some(sum_including_usize) = sum_including.to_usize() {
                if x_i < sum_including_usize {
                    j_i = j;
                    break;
                }
            } else {
                // If sum_including is too large, x_i is definitely smaller
                j_i = j;
                break;
            }

            sum_before = sum_including;

            if j == j_max {
                // x_i is beyond valid range, use actual layer size if available
                let max_size = layer_size_big.to_usize().unwrap_or(usize::MAX);
                return Err(MappingError::IndexOutOfRange {
                    index: x,
                    max: max_size,
                });
            }
        }

        // Set a_i := w - j_i
        vertex[i] = w - j_i;

        // Update d_{i+1} and x_{i+1}
        d_i = d_i - j_i;

        // Calculate the sum to subtract from x_i
        let mut sum_to_subtract = BigUint::zero();
        for j in j_min..j_i {
            let sub_d = d_i + j_i - j;
            let sub_v = remaining_dims - 1;
            sum_to_subtract += calculate_layer_size(sub_d, sub_v, w)?;
        }

        if let Some(sum_to_subtract_usize) = sum_to_subtract.to_usize() {
            x_i = x_i.saturating_sub(sum_to_subtract_usize);
        } else {
            // If sum_to_subtract is very large, set x_i to 0
            x_i = 0;
        }
    }

    // Set a_v := w - x_v - d_v
    if x_i + d_i > w {
        let max_size = layer_size_big.to_usize().unwrap_or(usize::MAX);
        return Err(MappingError::IndexOutOfRange {
            index: x,
            max: max_size,
        });
    }
    vertex[v - 1] = w - x_i - d_i;

    // Verify the result is in the correct layer
    let actual_layer = v * w - vertex.iter().sum::<usize>();
    if actual_layer != d {
        return Err(MappingError::InvalidLayer {
            expected: d,
            actual: actual_layer,
        });
    }

    Ok(vertex)
}

/// Non-uniform mapping function Ψ as defined in the paper
/// Paper Section 4: The non-uniform mapping Ψ is critical for security.
/// It maps integers uniformly to vertices within a specific layer,
/// providing target collision resistance for the signature schemes.
pub struct NonUniformMappingPsi {
    w: usize,
    v: usize,
    d: usize,
    layer_size: usize,
}

impl NonUniformMappingPsi {
    /// Create a new non-uniform mapping function for the given parameters
    pub fn new(w: usize, v: usize, d: usize) -> Result<Self, MappingError> {
        let layer_size_big = calculate_layer_size(d, v, w)?;
        let layer_size = layer_size_big
            .to_usize()
            .ok_or(MappingError::IntegerOverflow)?;

        Ok(NonUniformMappingPsi {
            w,
            v,
            d,
            layer_size,
        })
    }

    /// Map an integer to a vertex according to the non-uniform distribution
    /// Paper Definition (Section 4): Ψ maps Z → [w]^v with uniform distribution
    /// within the target layer d.
    pub fn map(&self, value: usize) -> Result<Vec<usize>, MappingError> {
        let index = value % self.layer_size;
        integer_to_vertex(index, self.w, self.v, self.d)
    }

    /// Calculate the probability of mapping to a specific vertex
    /// Paper Section 4: For TSL scheme, Pr[Ψ(z) = x] = 1/ℓ_d if x is in layer d,
    /// and 0 otherwise. This achieves optimal collision resistance μ²_ℓ(Ψ) = 1/ℓ_d.
    pub fn probability(&self, vertex: &[usize]) -> Result<f64, MappingError> {
        // Verify the vertex is in the correct layer
        let layer = self.v * self.w - vertex.iter().sum::<usize>();
        if layer != self.d {
            return Err(MappingError::InvalidLayer {
                expected: self.d,
                actual: layer,
            });
        }

        // In the uniform distribution within the layer, each vertex has equal probability
        Ok(1.0 / self.layer_size as f64)
    }

    /// Get the layer size
    pub fn layer_size(&self) -> usize {
        self.layer_size
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

    pub fn map(&self, i: usize) -> Result<Vec<usize>, MappingError> {
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

    pub fn map(&self, vertex: &[usize]) -> Result<usize, MappingError> {
        vertex_to_integer(vertex, self.w, self.v, self.d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertex_to_integer_basic() {
        // Test basic vertex to integer mapping
        // For a simple case, verify the mapping is injective

        // Binary hypercube [2]^3, layer 1
        // Vertices: (1,2,2), (2,1,2), (2,2,1)
        let v1 = vec![1, 2, 2];
        let v2 = vec![2, 1, 2];
        let v3 = vec![2, 2, 1];

        let i1 = vertex_to_integer(&v1, 2, 3, 1).unwrap();
        let i2 = vertex_to_integer(&v2, 2, 3, 1).unwrap();
        let i3 = vertex_to_integer(&v3, 2, 3, 1).unwrap();

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
            let vertex = integer_to_vertex(i, 2, 3, 1).unwrap();

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
                let layer_size = calculate_layer_size(d, v, w).unwrap().to_usize().unwrap();

                // Test round-trip for several integers
                for i in 0..layer_size.min(10) {
                    let vertex = integer_to_vertex(i, w, v, d).unwrap();
                    let i_back = vertex_to_integer(&vertex, w, v, d).unwrap();
                    assert_eq!(
                        i, i_back,
                        "Round trip failed for i={}, w={}, v={}, d={}",
                        i, w, v, d
                    );
                }
            }
        }
    }

    #[test]
    fn test_map_to_vertex_trait() {
        // Test the MapToVertex trait implementation
        let mapper = MapToVertex::new(4, 3, 2);

        // Map integer 0 to a vertex in layer 2
        let vertex = mapper.map(0).unwrap();

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
        let integer = mapper.map(&vertex).unwrap();

        // Verify the integer is in valid range
        let layer_size = calculate_layer_size(2, 3, 4).unwrap().to_usize().unwrap();
        assert!(integer < layer_size);
    }

    #[test]
    fn test_mapping_consistency() {
        // Test that all vertices in a layer map to unique integers
        let w = 3;
        let v = 3;
        let d = 3;

        // Test that the mapping is consistent
        // We'll generate all vertices using the integer_to_vertex function

        let layer_size = calculate_layer_size(d, v, w).unwrap().to_usize().unwrap();
        let mut mapped_integers = std::collections::HashSet::new();

        for i in 0..layer_size {
            let vertex = integer_to_vertex(i, w, v, d).unwrap();
            let mapped = vertex_to_integer(&vertex, w, v, d).unwrap();
            assert_eq!(i, mapped);
            mapped_integers.insert(mapped);
        }

        // All integers should be unique
        assert_eq!(mapped_integers.len(), layer_size);
    }

    #[test]
    fn test_paper_algorithm_bijection() {
        // Test the paper's algorithm specifically for various parameter sets
        let test_cases = vec![
            (2, 3, 1), // [2]^3, layer 1
            (3, 2, 2), // [3]^2, layer 2
            (3, 3, 3), // [3]^3, layer 3
            (4, 3, 4), // [4]^3, layer 4
            (4, 4, 6), // [4]^4, layer 6
        ];

        for (w, v, d) in test_cases {
            let layer_size = calculate_layer_size(d, v, w).unwrap().to_usize().unwrap();

            // Test forward and backward mapping for all integers in the layer
            for i in 0..layer_size {
                let vertex = integer_to_vertex(i, w, v, d).unwrap();

                // Verify vertex is valid
                assert_eq!(vertex.len(), v);
                for &coord in &vertex {
                    assert!(
                        coord >= 1 && coord <= w,
                        "Invalid coordinate {} for w={}",
                        coord,
                        w
                    );
                }

                // Verify vertex is in correct layer
                let layer_sum = v * w - vertex.iter().sum::<usize>();
                assert_eq!(
                    layer_sum, d,
                    "Vertex {:?} is in layer {} but expected layer {}",
                    vertex, layer_sum, d
                );

                // Test bijection property
                let i_back = vertex_to_integer(&vertex, w, v, d).unwrap();
                assert_eq!(
                    i, i_back,
                    "Bijection failed for i={}, w={}, v={}, d={}: vertex={:?}",
                    i, w, v, d, vertex
                );
            }
        }
    }

    #[test]
    fn test_edge_cases() {
        // Test edge cases for the new implementation

        // Single dimension case
        let vertex = integer_to_vertex(0, 3, 1, 2).unwrap();
        assert_eq!(vertex, vec![1]); // w - d = 3 - 2 = 1

        // Maximum layer case
        let w = 3;
        let v = 2;
        let d = 2 * (3 - 1); // Maximum layer
        let layer_size = calculate_layer_size(d, v, w).unwrap().to_usize().unwrap();
        assert_eq!(layer_size, 1); // Only one vertex in max layer

        let vertex = integer_to_vertex(0, w, v, d).unwrap();
        assert_eq!(vertex, vec![1, 1]); // All coordinates at minimum

        // Test invalid indices
        assert!(integer_to_vertex(layer_size, w, v, d,).is_err());
    }
}
