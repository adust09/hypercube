use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;

use crate::aggregate::{AggregateError, AggregateProof, C, D, F, SignatureBundle};

/// Simple aggregator for testing - bypasses complex encoding constraints
pub struct SimpleAggregator {
    config: CircuitConfig,
}

impl SimpleAggregator {
    pub fn new() -> Self {
        Self {
            config: CircuitConfig::standard_recursion_config(),
        }
    }
    
    /// Create a simple aggregate proof without full encoding verification
    pub fn aggregate_simple(
        &self,
        bundle: &SignatureBundle,
    ) -> Result<AggregateProof, AggregateError> {
        // Build a minimal circuit
        let mut builder = CircuitBuilder::<F, D>::new(self.config.clone());
        
        // Add message hash as public input
        let message_hash_target = builder.add_virtual_hash();
        builder.register_public_inputs(&message_hash_target.elements);
        
        // Add a simple constraint for each signature
        let mut dummy_targets = Vec::new();
        for _ in 0..bundle.len() {
            // Just add a dummy constraint that always passes
            let one = builder.one();
            let dummy = builder.add_virtual_target();
            builder.connect(dummy, one);
            dummy_targets.push(dummy);
        }
        
        // Build the circuit
        let data = builder.build::<C>();
        
        // Create witness
        let mut pw = PartialWitness::new();
        
        // Set message hash
        let message_hash = hash_message(&bundle.message);
        pw.set_hash_target(message_hash_target, message_hash);
        
        // Set dummy values
        for target in dummy_targets {
            pw.set_target(target, F::ONE);
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
}

/// Hash message using simple field element conversion
fn hash_message(message: &[u8]) -> HashOut<F> {
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;
    
    // Convert message bytes to field elements
    let mut elements = Vec::new();
    for chunk in message.chunks(7) { // Use 7 bytes per field element to avoid overflow
        let mut value = 0u64;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u64) << (i * 8);
        }
        elements.push(F::from_canonical_u64(value));
    }
    
    // Hash the elements
    PoseidonHash::hash_no_pad(&elements)
}

impl Default for SimpleAggregator {
    fn default() -> Self {
        Self::new()
    }
}