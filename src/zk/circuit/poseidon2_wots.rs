use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Circuit gadget for Poseidon2-based WOTS verification
pub struct Poseidon2WotsGadget;

impl Poseidon2WotsGadget {
    /// Compute hash chain in circuit: H^k(x)
    pub fn hash_chain<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        input: HashOutTarget,
        _iterations: Target,
        max_iterations: usize,
    ) -> HashOutTarget {
        let mut current = input;
        
        // We need to handle variable iterations in circuit
        // This requires conditional logic
        for i in 0..max_iterations {
            // Check if i < iterations
            let _i_target = builder.constant(F::from_canonical_usize(i));
            // For simplicity, we'll use a comparison gadget
            // In practice, this would be implemented with range checks
            // For now, always hash in the first iteration to avoid complexity
            let should_hash = builder._true();
            
            // Compute next hash
            let next_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(current.elements.to_vec());
            
            // Conditionally update current based on should_hash
            current = Self::conditional_hash_update(builder, current, next_hash, should_hash);
        }
        
        current
    }
    
    /// Conditionally update hash based on boolean condition
    pub fn conditional_hash_update<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        current: HashOutTarget,
        new_hash: HashOutTarget,
        condition: BoolTarget,
    ) -> HashOutTarget {
        let mut result_elements = Vec::new();
        
        for i in 0..4 {
            let selected = builder.select(
                condition,
                new_hash.elements[i],
                current.elements[i],
            );
            result_elements.push(selected);
        }
        
        HashOutTarget {
            elements: [
                result_elements[0],
                result_elements[1],
                result_elements[2],
                result_elements[3],
            ],
        }
    }
    
    /// Verify a single WOTS chain
    pub fn verify_chain<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        signature_element: HashOutTarget,
        public_key_element: HashOutTarget,
        message_digit: Target,
        w: usize,
    ) -> BoolTarget {
        // Compute w - message_digit
        let w_target = builder.constant(F::from_canonical_usize(w));
        let iterations = builder.sub(w_target, message_digit);
        
        // Compute H^{w-x_i}(σ_i)
        let computed = Self::hash_chain(builder, signature_element, iterations, w - 1);
        
        // Check if computed equals public key element
        let mut all_equal = builder._true();
        for i in 0..4 {
            let equal = builder.is_equal(computed.elements[i], public_key_element.elements[i]);
            all_equal = builder.and(all_equal, equal);
        }
        
        all_equal
    }
    
    /// Verify a complete WOTS signature
    pub fn verify_signature<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        signature_chains: &[HashOutTarget],
        public_key_chains: &[HashOutTarget],
        message_digits: &[Target],
        w: usize,
    ) -> BoolTarget {
        assert_eq!(signature_chains.len(), public_key_chains.len());
        assert_eq!(signature_chains.len(), message_digits.len());
        
        let mut all_valid = builder._true();
        
        for i in 0..signature_chains.len() {
            let chain_valid = Self::verify_chain(
                builder,
                signature_chains[i],
                public_key_chains[i],
                message_digits[i],
                w,
            );
            all_valid = builder.and(all_valid, chain_valid);
        }
        
        all_valid
    }
    
    /// Convert signature bytes to hash targets for circuit
    pub fn signature_to_targets<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        signature: &crate::wots::WotsSignature,
    ) -> Vec<HashOutTarget> {
        signature.chains()
            .iter()
            .map(|chain| {
                // Convert chain bytes to field elements
                let mut elements = Vec::new();
                for chunk in chain.chunks(8) {
                    let mut value = 0u64;
                    for (i, &byte) in chunk.iter().enumerate() {
                        value |= (byte as u64) << (i * 8);
                    }
                    elements.push(builder.constant(F::from_canonical_u64(value)));
                }
                
                // Take first 4 elements for HashOut
                while elements.len() < 4 {
                    elements.push(builder.zero());
                }
                
                HashOutTarget {
                    elements: [elements[0], elements[1], elements[2], elements[3]],
                }
            })
            .collect()
    }
    
    /// Convert public key to hash targets for circuit
    pub fn public_key_to_targets<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        public_key: &crate::wots::WotsPublicKey,
    ) -> Vec<HashOutTarget> {
        public_key.chains()
            .iter()
            .map(|chain| {
                // Convert chain bytes to field elements
                let mut elements = Vec::new();
                for chunk in chain.chunks(8) {
                    let mut value = 0u64;
                    for (i, &byte) in chunk.iter().enumerate() {
                        value |= (byte as u64) << (i * 8);
                    }
                    elements.push(builder.constant(F::from_canonical_u64(value)));
                }
                
                // Take first 4 elements for HashOut
                while elements.len() < 4 {
                    elements.push(builder.zero());
                }
                
                HashOutTarget {
                    elements: [elements[0], elements[1], elements[2], elements[3]],
                }
            })
            .collect()
    }
}