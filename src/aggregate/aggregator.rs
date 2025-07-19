use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::Hasher;

use crate::aggregate::{AggregateError, AggregateProof, C, D, F, PublicInputs, SignatureBundle};
use crate::core::encoding::EncodingScheme;
use crate::crypto::hash::HashFunction;
use crate::crypto::poseidon2::Poseidon2Hash;
use crate::aggregate::aggregator_full;

/// Targets for a single signature verification
struct SignatureTargets {
    signature: Vec<HashOutTarget>,
    public_key: Vec<HashOutTarget>,
    message_hash: HashOutTarget,
}

use plonky2::hash::hash_types::HashOutTarget;

/// Aggregates multiple signatures into a single ZK proof
pub struct Aggregator {
    config: CircuitConfig,
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            config: CircuitConfig::standard_recursion_config(),
        }
    }
    
    /// Create an aggregate proof from a bundle of signatures
    pub fn aggregate(
        &self,
        bundle: &SignatureBundle,
        scheme: &dyn EncodingScheme,
    ) -> Result<AggregateProof, AggregateError> {
        // Build the circuit
        let mut builder = CircuitBuilder::<F, D>::new(self.config.clone());
        
        // Hash the message
        let message_hash = Self::hash_message(&bundle.message);
        
        // Create public inputs
        let public_inputs = self.create_public_inputs(bundle, message_hash)?;
        
        // Add public input targets
        let public_input_targets = self.register_public_inputs(&mut builder, &public_inputs);
        
        // Store signature and verification targets
        let mut all_targets = Vec::new();
        
        // Add signature verification logic for each signature
        for (i, (signature, public_key)) in bundle.signatures.iter()
            .zip(bundle.public_keys.iter())
            .enumerate()
        {
            let targets = self.add_signature_verification(
                &mut builder,
                i,
                signature,
                public_key,
                &message_hash,
                scheme,
            )?;
            all_targets.push(targets);
        }
        
        // Build the circuit
        let data = builder.build::<C>();
        
        // Create witness and set values
        let mut pw = PartialWitness::new();
        
        // Set public inputs
        let public_elements = public_inputs.to_field_elements();
        for (i, &target) in public_input_targets.iter().enumerate() {
            if i < public_elements.len() {
                pw.set_target(target, public_elements[i]);
            }
        }
        
        // Set witness values for each signature verification
        for (i, targets) in all_targets.iter().enumerate() {
            self.set_signature_witness(
                &mut pw,
                targets,
                &bundle.signatures[i],
                &bundle.public_keys[i],
                &message_hash,
            );
        }
        
        // Generate the proof
        let proof = data.prove(pw)
            .map_err(|e| AggregateError::ProofGenerationError(e.to_string()))?;
        
        Ok(AggregateProof {
            proof,
            circuit_data: data,
            num_signatures: bundle.len(),
        })
    }
    
    /// Hash the message using Poseidon2
    pub fn hash_message(message: &[u8]) -> HashOut<F> {
        let hasher = Poseidon2Hash::new();
        let hash_bytes = hasher.hash(message);
        
        // Convert to field elements
        let mut elements = Vec::new();
        for chunk in hash_bytes.chunks(8) {
            let mut value = 0u64;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u64) << (i * 8);
            }
            elements.push(F::from_canonical_u64(value));
        }
        
        // Ensure we have exactly 4 elements for HashOut
        while elements.len() < 4 {
            elements.push(F::ZERO);
        }
        
        HashOut {
            elements: [elements[0], elements[1], elements[2], elements[3]],
        }
    }
    
    /// Create public inputs from the signature bundle
    fn create_public_inputs(
        &self,
        bundle: &SignatureBundle,
        message_hash: HashOut<F>,
    ) -> Result<PublicInputs, AggregateError> {
        // Compute commitments to public keys
        let public_key_commitments = bundle.public_keys
            .iter()
            .map(|pk| {
                // Hash all chains of the public key
                let mut elements = Vec::new();
                for chain in pk.chains() {
                    for chunk in chain.chunks(8) {
                        let mut value = 0u64;
                        for (i, &byte) in chunk.iter().enumerate() {
                            value |= (byte as u64) << (i * 8);
                        }
                        elements.push(F::from_canonical_u64(value));
                    }
                }
                let hash = PoseidonHash::hash_no_pad(&elements);
                hash.elements.to_vec()
            })
            .collect();
        
        Ok(PublicInputs {
            message_hash: message_hash.elements.to_vec(),
            public_key_commitments,
        })
    }
    
    /// Register public inputs in the circuit
    fn register_public_inputs(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        public_inputs: &PublicInputs,
    ) -> Vec<plonky2::iop::target::Target> {
        let mut targets = Vec::new();
        
        // Register message hash
        for _element in &public_inputs.message_hash {
            let target = builder.add_virtual_target();
            builder.register_public_input(target);
            targets.push(target);
        }
        
        // Register public key commitments
        for commitment in &public_inputs.public_key_commitments {
            for _element in commitment {
                let target = builder.add_virtual_target();
                builder.register_public_input(target);
                targets.push(target);
            }
        }
        
        targets
    }
    
    /// Add signature verification logic to the circuit
    fn add_signature_verification(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        _index: usize,
        signature: &crate::wots::WotsSignature,
        public_key: &crate::wots::WotsPublicKey,
        _message_hash: &HashOut<F>,
        scheme: &dyn EncodingScheme,
    ) -> Result<SignatureTargets, AggregateError> {
        // Create targets for signature chains
        let signature_targets: Vec<_> = signature.chains()
            .iter()
            .map(|_| builder.add_virtual_hash())
            .collect();
        
        // Create targets for public key chains
        let public_key_targets: Vec<_> = public_key.chains()
            .iter()
            .map(|_| builder.add_virtual_hash())
            .collect();
        
        // Create message hash target
        let message_hash_target = builder.add_virtual_hash();
        
        // Use the complete signature verification
        aggregator_full::add_complete_signature_verification(
            builder,
            &signature_targets,
            &public_key_targets,
            message_hash_target,
            scheme,
            scheme.name(),
        )?;
        
        Ok(SignatureTargets {
            signature: signature_targets,
            public_key: public_key_targets,
            message_hash: message_hash_target,
        })
    }
    
    /// Set witness values for signature verification
    fn set_signature_witness(
        &self,
        witness: &mut PartialWitness<F>,
        targets: &SignatureTargets,
        signature: &crate::wots::WotsSignature,
        public_key: &crate::wots::WotsPublicKey,
        message_hash: &HashOut<F>,
    ) {
        // Set message hash
        witness.set_hash_target(targets.message_hash, *message_hash);
        
        // Set signature chains
        for (i, chain) in signature.chains().iter().enumerate() {
            if i < targets.signature.len() {
                let hash_out = Self::bytes_to_hash_out(chain);
                witness.set_hash_target(targets.signature[i], hash_out);
            }
        }
        
        // Set public key chains
        for (i, chain) in public_key.chains().iter().enumerate() {
            if i < targets.public_key.len() {
                let hash_out = Self::bytes_to_hash_out(chain);
                witness.set_hash_target(targets.public_key[i], hash_out);
            }
        }
    }
    
    /// Convert bytes to HashOut
    fn bytes_to_hash_out(bytes: &[u8]) -> HashOut<F> {
        let mut elements = Vec::new();
        
        for chunk in bytes.chunks(8) {
            let mut value = 0u64;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u64) << (i * 8);
            }
            elements.push(F::from_canonical_u64(value));
        }
        
        // Ensure we have exactly 4 elements
        while elements.len() < 4 {
            elements.push(F::ZERO);
        }
        
        HashOut {
            elements: [elements[0], elements[1], elements[2], elements[3]],
        }
    }
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aggregator_creation() {
        let _aggregator = Aggregator::new();
        // Basic creation test
        assert!(true);
    }
    
    #[test]
    fn test_message_hashing() {
        let message = b"test message";
        let hash = Aggregator::hash_message(message);
        
        // Verify we get a valid hash output
        assert_eq!(hash.elements.len(), 4);
    }
}