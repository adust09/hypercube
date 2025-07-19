use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::zk::circuit::poseidon2_wots::Poseidon2WotsGadget;
use crate::zk::circuit::encoding_constraints::EncodingConstraints;

/// Circuit for batch verification of multiple WOTS signatures
pub struct BatchVerifyCircuit;

impl BatchVerifyCircuit {
    /// Add batch verification constraints to the circuit
    pub fn add_batch_verification<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        signatures: &[Vec<HashOutTarget>],  // Each inner vec is one signature's chains
        public_keys: &[Vec<HashOutTarget>], // Each inner vec is one public key's chains
        message_digits: &[Vec<Target>],      // Each inner vec is one signature's message digits
        w: usize,
    ) -> BoolTarget {
        assert_eq!(signatures.len(), public_keys.len());
        assert_eq!(signatures.len(), message_digits.len());
        
        let mut all_valid = builder._true();
        
        // Verify each signature
        for i in 0..signatures.len() {
            let sig_valid = Poseidon2WotsGadget::verify_signature(
                builder,
                &signatures[i],
                &public_keys[i],
                &message_digits[i],
                w,
            );
            
            all_valid = builder.and(all_valid, sig_valid);
        }
        
        all_valid
    }
    
    /// Add constraints for message encoding verification
    pub fn add_encoding_constraints<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        message_hash: HashOutTarget,
        message_digits: &[Vec<Target>],
        encoding_type: &str,
        w: usize,
        v: usize,
    ) {
        // For each signature, verify the encoding constraints
        for digits in message_digits {
            match encoding_type {
                "TSL" => {
                    // TSL maps to a single layer - use default parameters for now
                    let d0 = v * (w - 1) / 2; // Middle layer
                    let valid = EncodingConstraints::add_tsl_constraints(
                        builder,
                        message_hash,
                        digits,
                        w,
                        v,
                        d0,
                    );
                    builder.assert_one(valid.target);
                }
                "TL1C" => {
                    // TL1C maps to multiple layers with 1-chain checksum
                    let d0 = v * (w - 1) / 3;
                    let checksum = builder.add_virtual_target();
                    let valid = EncodingConstraints::add_tl1c_constraints(
                        builder,
                        message_hash,
                        digits,
                        checksum,
                        w,
                        v,
                        d0,
                    );
                    builder.assert_one(valid.target);
                }
                "TLFC" => {
                    // TLFC maps to multiple layers with full checksum
                    let d0 = v * (w - 1) / 3;
                    let c = 4; // Number of checksum chains
                    let mut checksums = Vec::new();
                    for _ in 0..c {
                        checksums.push(builder.add_virtual_target());
                    }
                    let valid = EncodingConstraints::add_tlfc_constraints(
                        builder,
                        message_hash,
                        digits,
                        &checksums,
                        w,
                        v,
                        d0,
                        c,
                    );
                    builder.assert_one(valid.target);
                }
                _ => panic!("Unknown encoding type"),
            }
        }
    }
    
    /// Create a complete batch verification circuit
    pub fn build_circuit<F: RichField + Extendable<D>, const D: usize>(
        num_signatures: usize,
        chains_per_signature: usize,
        w: usize,
        encoding_type: &str,
    ) -> (CircuitBuilder<F, D>, BatchVerifyTargets) {
        let mut builder = CircuitBuilder::<F, D>::new(plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config());
        
        // Create targets for inputs
        let message_hash = builder.add_virtual_hash();
        builder.register_public_inputs(&message_hash.elements);
        
        let mut signature_targets = Vec::new();
        let mut public_key_targets = Vec::new();
        let mut message_digit_targets = Vec::new();
        
        for _ in 0..num_signatures {
            // Signature chains
            let mut sig_chains = Vec::new();
            for _ in 0..chains_per_signature {
                sig_chains.push(builder.add_virtual_hash());
            }
            signature_targets.push(sig_chains);
            
            // Public key chains (registered as public inputs)
            let mut pk_chains = Vec::new();
            for _ in 0..chains_per_signature {
                let pk_chain = builder.add_virtual_hash();
                builder.register_public_inputs(&pk_chain.elements);
                pk_chains.push(pk_chain);
            }
            public_key_targets.push(pk_chains);
            
            // Message digits
            let mut digits = Vec::new();
            for _ in 0..chains_per_signature {
                digits.push(builder.add_virtual_target());
            }
            message_digit_targets.push(digits);
        }
        
        // Add encoding constraints
        Self::add_encoding_constraints(
            &mut builder,
            message_hash,
            &message_digit_targets,
            encoding_type,
            w,
            chains_per_signature, // Using chains_per_signature as v (dimension)
        );
        
        // Add batch verification constraints
        let all_valid = Self::add_batch_verification(
            &mut builder,
            &signature_targets,
            &public_key_targets,
            &message_digit_targets,
            w,
        );
        
        // Assert all signatures are valid
        builder.assert_one(all_valid.target);
        
        let targets = BatchVerifyTargets {
            message_hash,
            signatures: signature_targets,
            public_keys: public_key_targets,
            message_digits: message_digit_targets,
        };
        
        (builder, targets)
    }
}

/// Targets for batch verification circuit
pub struct BatchVerifyTargets {
    pub message_hash: HashOutTarget,
    pub signatures: Vec<Vec<HashOutTarget>>,
    pub public_keys: Vec<Vec<HashOutTarget>>,
    pub message_digits: Vec<Vec<Target>>,
}