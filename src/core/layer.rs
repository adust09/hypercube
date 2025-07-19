// Layer calculations for hypercube

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Calculate the layer of a vertex: d = vw - Σx_i
pub fn calculate_layer(vertex: &[usize], w: usize) -> usize {
    let v = vertex.len();
    let sum: usize = vertex.iter().sum();
    v * w - sum
}

/// Calculate the size of layer d in hypercube [w]^v
/// Formula: ℓ_d = Σ_{s=0}^{⌊d/w⌋} (-1)^s · C(v,s) · C(d-s·w+v-1, v-1)
pub fn calculate_layer_size(d: usize, v: usize, w: usize) -> usize {
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
        // Calculate C(v, s)
        let binom_v_s = binomial(v, s);

        // Calculate d - s*w + v - 1
        let inner = d as i64 - (s * w) as i64 + v as i64 - 1;

        // If inner < v-1, the binomial coefficient is 0
        if inner < (v - 1) as i64 {
            continue;
        }

        // Calculate C(d-s*w+v-1, v-1)
        let binom_inner = binomial(inner as usize, v - 1);

        // Add or subtract based on (-1)^s
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
    sum.to_string().parse().unwrap_or(0)
}

/// Calculate binomial coefficient C(n, k)
fn binomial(n: usize, k: usize) -> BigUint {
    if k > n {
        return BigUint::zero();
    }

    if k == 0 || k == n {
        return BigUint::one();
    }

    // Use the more efficient formula: C(n,k) = n! / (k! * (n-k)!)
    // But calculate it as: C(n,k) = (n * (n-1) * ... * (n-k+1)) / (k * (k-1) * ... * 1)
    let k = k.min(n - k); // Take advantage of symmetry

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
}
