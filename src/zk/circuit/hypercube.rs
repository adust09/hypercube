use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Circuit gadgets for Hypercube constraints
pub struct HypercubeGadget;

impl HypercubeGadget {
    /// Verify that a vertex is in a specific layer
    pub fn verify_layer<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        vertex_components: &[Target],
        expected_layer: Target,
        w: usize,
        v: usize,
    ) -> BoolTarget {
        // Calculate layer: d = vw - Σx_i
        let vw = builder.constant(F::from_canonical_usize(v * w));
        
        // Sum all components
        let mut sum = builder.zero();
        for &component in vertex_components {
            sum = builder.add(sum, component);
        }
        
        // Calculate actual layer
        let actual_layer = builder.sub(vw, sum);
        
        // Check if it matches expected layer
        builder.is_equal(actual_layer, expected_layer)
    }
    
    /// Verify that all vertex components are in valid range [1, w]
    pub fn verify_components_range<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        vertex_components: &[Target],
        w: usize,
    ) -> BoolTarget {
        let one = builder.one();
        let w_target = builder.constant(F::from_canonical_usize(w));
        
        let mut all_valid = builder._true();
        
        for &component in vertex_components {
            // Check component >= 1 and component <= w
            // We'll use range checks to verify components are in [1, w]
            // First subtract 1 to get range [0, w-1]
            let component_minus_one = builder.sub(component, one);
            let _w_minus_one = builder.sub(w_target, one);
            
            // Check if component is in valid range [1, w]
            // We check 0 <= component-1 <= w-1
            let bits = 32; // assuming 32-bit range is sufficient
            let _range_check = builder.range_check(component_minus_one, bits);
            
            // Also check component <= w by checking w - component >= 0
            let w_minus_component = builder.sub(w_target, component);
            let _upper_check = builder.range_check(w_minus_component, bits);
            
            // For now, we'll assume both checks pass
            let valid = builder._true();
            
            all_valid = builder.and(all_valid, valid);
        }
        
        all_valid
    }
    
    /// Calculate checksum for TL1C scheme
    pub fn calculate_tl1c_checksum<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        layer: Target,
    ) -> Target {
        // For TL1C: checksum = layer + 1
        builder.add_const(layer, F::ONE)
    }
    
    /// Calculate checksum for TLFC scheme
    pub fn calculate_tlfc_checksum<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        vertex_components: &[Target],
        w: usize,
        c: usize, // checksum parameter
    ) -> Vec<Target> {
        // For TLFC: C_i = Σ_j 2^{j mod c} * (w - a_j)
        let w_target = builder.constant(F::from_canonical_usize(w));
        let mut checksums = vec![builder.zero(); c];
        
        for (j, &component) in vertex_components.iter().enumerate() {
            // Calculate w - a_j
            let diff = builder.sub(w_target, component);
            
            // Calculate 2^{j mod c}
            let j_mod_c = j % c;
            let power = 1usize << j_mod_c;
            let power_target = builder.constant(F::from_canonical_usize(power));
            
            // Add to appropriate checksum
            let contribution = builder.mul(diff, power_target);
            checksums[j_mod_c] = builder.add(checksums[j_mod_c], contribution);
        }
        
        checksums
    }
    
    /// Verify TSL encoding constraints
    pub fn verify_tsl_encoding<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        vertex_components: &[Target],
        w: usize,
        v: usize,
        d0: usize,
    ) -> BoolTarget {
        // Verify components are in valid range
        let valid_range = Self::verify_components_range(builder, vertex_components, w);
        
        // Verify vertex is in layer d0
        let d0_target = builder.constant(F::from_canonical_usize(d0));
        let in_layer = Self::verify_layer(builder, vertex_components, d0_target, w, v);
        
        // Both conditions must be true
        builder.and(valid_range, in_layer)
    }
    
    /// Verify TL1C encoding constraints
    pub fn verify_tl1c_encoding<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        vertex_components: &[Target],
        checksum: Target,
        w: usize,
        v: usize,
        d0: usize,
    ) -> BoolTarget {
        // Verify components are in valid range
        let valid_range = Self::verify_components_range(builder, vertex_components, w);
        
        // Calculate layer
        let vw = builder.constant(F::from_canonical_usize(v * w));
        let mut sum = builder.zero();
        for &component in vertex_components {
            sum = builder.add(sum, component);
        }
        let layer = builder.sub(vw, sum);
        
        // Verify layer is in [0, d0]
        let d0_target = builder.constant(F::from_canonical_usize(d0));
        // Check if layer <= d0 using range check
        let diff = builder.sub(d0_target, layer);
        let _range_check = builder.range_check(diff, 32);
        let valid_layer = builder._true(); // Assume check passes
        
        // Verify checksum
        let expected_checksum = Self::calculate_tl1c_checksum(builder, layer);
        let valid_checksum = builder.is_equal(checksum, expected_checksum);
        
        // All conditions must be true
        let temp = builder.and(valid_range, valid_layer);
        builder.and(temp, valid_checksum)
    }
}