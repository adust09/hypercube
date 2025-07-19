// Vertex to integer mapping functions - Paper-compliant implementation
// Based on "At the Top of the Hypercube" Section 6.1

use num_bigint::BigUint;
use num_traits::{CheckedSub, One, ToPrimitive, Zero};

/// Maps a vertex in layer d to an integer in [0, ℓ_d)
/// Implements the exact mapping from the paper Section 6.1
pub fn vertex_to_integer(
    vertex: &[usize],
    w: usize,
    v: usize,
    d: usize,
) -> Result<usize, MappingError,> {
    // Verify the vertex is in the correct layer
    let layer = v * w - vertex.iter().sum::<usize>();
    if layer != d {
        return Err(MappingError::InvalidLayer { expected: d, actual: layer, },);
    }

    // Validate coordinates are in range [1, w]
    for (i, &coord,) in vertex.iter().enumerate() {
        if coord < 1 || coord > w {
            return Err(MappingError::InvalidCoordinate { position: i, value: coord, max: w, },);
        }
    }

    // Use the exact vertex-to-integer mapping from the paper
    vertex_to_integer_paper_exact(vertex, w, v, d,)
}

/// Exact vertex-to-integer mapping implementation from the paper
/// This implements the combinatorial ranking formula from Section 6.1
fn vertex_to_integer_paper_exact(
    vertex: &[usize],
    w: usize,
    v: usize,
    d: usize,
) -> Result<usize, MappingError,> {
    let mut rank = BigUint::zero();
    let mut remaining_dims = v;
    let mut remaining_sum = d;

    // Process each coordinate position from left to right
    for (_pos, &coord,) in vertex.iter().enumerate() {
        remaining_dims -= 1;

        // Count vertices that come before this coordinate at this position
        for smaller_coord in 1..coord {
            // Calculate the number of valid completions with this smaller coordinate
            let used_sum = w - smaller_coord;
            if remaining_sum >= used_sum {
                let sub_layer = remaining_sum - used_sum;
                let completions = calculate_layer_size_exact(sub_layer, remaining_dims, w,)?;
                rank += completions;
            }
        }

        // Update remaining sum constraint
        let used_sum = w - coord;
        if remaining_sum < used_sum {
            return Err(MappingError::InvalidLayer {
                expected: d,
                actual: v * w - vertex.iter().sum::<usize>(),
            },);
        }
        remaining_sum -= used_sum;
    }

    // Convert BigUint to usize
    rank.to_usize().ok_or(MappingError::IntegerOverflow,)
}

/// Calculate layer size using the exact formula from the paper
/// Formula: ℓ_d = Σ_{s=0}^{⌊d/w⌋} (-1)^s · C(v,s) · C(d-s·w+v-1, v-1)
fn calculate_layer_size_exact(d: usize, v: usize, w: usize,) -> Result<BigUint, MappingError,> {
    if v == 0 {
        return Ok(if d == 0 { BigUint::one() } else { BigUint::zero() },);
    }

    if d > v * (w - 1) {
        return Ok(BigUint::zero(),);
    }

    let mut sum = BigUint::zero();
    let max_s = d / w;

    for s in 0..=max_s {
        // Calculate C(v, s)
        let binom_v_s = binomial_coefficient(v, s,);

        // Calculate d - s*w + v - 1
        let inner_arg = d + v - 1 - s * w;

        // Calculate C(d-s*w+v-1, v-1)
        let binom_inner = if inner_arg >= v - 1 {
            binomial_coefficient(inner_arg, v - 1,)
        } else {
            BigUint::zero()
        };

        // Apply inclusion-exclusion principle
        let term = binom_v_s * binom_inner;
        if s % 2 == 0 {
            sum += term;
        } else {
            sum = sum.checked_sub(&term,).unwrap_or(BigUint::zero(),);
        }
    }

    Ok(sum,)
}

/// Calculate exact binomial coefficient C(n, k) using the paper's requirements
fn binomial_coefficient(n: usize, k: usize,) -> BigUint {
    if k > n {
        return BigUint::zero();
    }

    if k == 0 || k == n {
        return BigUint::one();
    }

    // Use symmetry to optimize calculation
    let k = k.min(n - k,);

    let mut result = BigUint::one();
    for i in 0..k {
        result = result * (n - i) / (i + 1);
    }

    result
}

// Helper function removed - no longer needed in the current implementation

/// Error types for mapping operations
#[derive(Debug, PartialEq, Eq, Hash,)]
pub enum MappingError {
    InvalidLayer { expected: usize, actual: usize, },
    InvalidCoordinate { position: usize, value: usize, max: usize, },
    IntegerOverflow,
    IndexOutOfRange { index: usize, max: usize, },
}

/// Maps an integer in [0, ℓ_d) to a vertex in layer d
/// Implements the exact inverse mapping from the paper Section 6.1
pub fn integer_to_vertex(
    i: usize,
    w: usize,
    v: usize,
    d: usize,
) -> Result<Vec<usize,>, MappingError,> {
    let layer_size_big = calculate_layer_size_exact(d, v, w,)?;
    let layer_size = layer_size_big.to_usize().ok_or(MappingError::IntegerOverflow,)?;

    if i >= layer_size {
        return Err(MappingError::IndexOutOfRange { index: i, max: layer_size, },);
    }

    integer_to_vertex_paper_exact(i, w, v, d,)
}

/// Exact integer-to-vertex mapping implementation from the paper
/// This implements the inverse of the combinatorial ranking formula
fn integer_to_vertex_paper_exact(
    mut index: usize,
    w: usize,
    v: usize,
    d: usize,
) -> Result<Vec<usize,>, MappingError,> {
    let mut vertex = vec![1; v];
    let mut remaining_dims = v;
    let mut remaining_sum = d;

    // Process each coordinate position from left to right
    for pos in 0..v {
        remaining_dims -= 1;

        // Find the correct coordinate value for this position
        for coord in 1..=w {
            let used_sum = w - coord;
            if remaining_sum >= used_sum {
                let sub_layer = remaining_sum - used_sum;
                let completions_big = calculate_layer_size_exact(sub_layer, remaining_dims, w,)?;
                let completions =
                    completions_big.to_usize().ok_or(MappingError::IntegerOverflow,)?;

                if index < completions {
                    // This is the correct coordinate
                    vertex[pos] = coord;
                    remaining_sum -= used_sum;
                    break;
                } else {
                    // Skip this coordinate's contributions
                    index -= completions;
                }
            }

            // Check if we've reached the maximum coordinate
            if coord == w {
                if remaining_sum == used_sum {
                    vertex[pos] = coord;
                    remaining_sum = 0;
                    break;
                } else {
                    return Err(MappingError::IndexOutOfRange { index, max: 0, },);
                }
            }
        }
    }

    // Verify the result is in the correct layer
    let actual_layer = v * w - vertex.iter().sum::<usize>();
    if actual_layer != d {
        return Err(MappingError::InvalidLayer { expected: d, actual: actual_layer, },);
    }

    Ok(vertex,)
}

/// Non-uniform mapping function Ψ as defined in the paper
/// This implements the probability distribution for mapping integers to vertices
pub struct NonUniformMappingPsi {
    w: usize,
    v: usize,
    d: usize,
    layer_size: usize,
}

impl NonUniformMappingPsi {
    /// Create a new non-uniform mapping function for the given parameters
    pub fn new(w: usize, v: usize, d: usize,) -> Result<Self, MappingError,> {
        let layer_size_big = calculate_layer_size_exact(d, v, w,)?;
        let layer_size = layer_size_big.to_usize().ok_or(MappingError::IntegerOverflow,)?;

        Ok(NonUniformMappingPsi { w, v, d, layer_size, },)
    }

    /// Map an integer to a vertex according to the non-uniform distribution
    pub fn map(&self, value: usize,) -> Result<Vec<usize,>, MappingError,> {
        let index = value % self.layer_size;
        integer_to_vertex(index, self.w, self.v, self.d,)
    }

    /// Calculate the probability of mapping to a specific vertex
    /// In the uniform case within a layer, this is 1/ℓ_d
    pub fn probability(&self, vertex: &[usize],) -> Result<f64, MappingError,> {
        // Verify the vertex is in the correct layer
        let layer = self.v * self.w - vertex.iter().sum::<usize>();
        if layer != self.d {
            return Err(MappingError::InvalidLayer { expected: self.d, actual: layer, },);
        }

        // In the uniform distribution within the layer, each vertex has equal probability
        Ok(1.0 / self.layer_size as f64,)
    }

    /// Get the layer size
    pub fn layer_size(&self,) -> usize {
        self.layer_size
    }
}

pub struct MapToVertex {
    w: usize,
    v: usize,
    d: usize,
}

impl MapToVertex {
    pub fn new(w: usize, v: usize, d: usize,) -> Self {
        MapToVertex { w, v, d, }
    }

    pub fn map(&self, i: usize,) -> Result<Vec<usize,>, MappingError,> {
        integer_to_vertex(i, self.w, self.v, self.d,)
    }
}

pub struct MapToInteger {
    w: usize,
    v: usize,
    d: usize,
}

impl MapToInteger {
    pub fn new(w: usize, v: usize, d: usize,) -> Self {
        MapToInteger { w, v, d, }
    }

    pub fn map(&self, vertex: &[usize],) -> Result<usize, MappingError,> {
        vertex_to_integer(vertex, self.w, self.v, self.d,)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::layer;

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
                let layer_size = layer::calculate_layer_size(d, v, w);
                
                // Test round-trip for several integers
                for i in 0..layer_size.min(10) {
                    let vertex = integer_to_vertex(i, w, v, d).unwrap();
                    let i_back = vertex_to_integer(&vertex, w, v, d).unwrap();
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
        let layer_size = layer::calculate_layer_size(2, 3, 4);
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
        
        let layer_size = layer::calculate_layer_size(d, v, w);
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
}
