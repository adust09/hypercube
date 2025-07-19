pub mod batch_verify;
pub mod hypercube;
pub mod poseidon2_wots;
pub mod encoding_constraints;

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Common circuit utilities
pub struct CircuitUtils;

impl CircuitUtils {
    /// Assert that two targets are equal
    pub fn assert_equal<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: Target,
        b: Target,
    ) {
        builder.connect(a, b);
    }
    
    /// Assert that a target equals a constant
    pub fn assert_constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        target: Target,
        constant: F,
    ) {
        let constant_target = builder.constant(constant);
        builder.connect(target, constant_target);
    }
    
    /// Convert bytes to field element targets
    pub fn bytes_to_targets<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        bytes: &[u8],
    ) -> Vec<Target> {
        bytes.iter()
            .map(|&b| builder.constant(F::from_canonical_u8(b)))
            .collect()
    }
    
    /// Pack byte targets into field element targets (8 bytes per element)
    pub fn pack_bytes_to_field_elements<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        byte_targets: &[Target],
    ) -> Vec<Target> {
        let mut field_elements = Vec::new();
        
        for chunk in byte_targets.chunks(8) {
            let mut value = builder.zero();
            let mut multiplier = builder.one();
            
            for &byte_target in chunk {
                let shifted = builder.mul(byte_target, multiplier);
                value = builder.add(value, shifted);
                
                // Multiply by 256 for next byte
                let two_five_six = builder.constant(F::from_canonical_u16(256));
                multiplier = builder.mul(multiplier, two_five_six);
            }
            
            field_elements.push(value);
        }
        
        field_elements
    }
}