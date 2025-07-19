pub mod aggregator;
pub mod aggregator_full;
pub mod aggregator_simple;
pub mod signature_set;
pub mod verifier;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use thiserror::Error;

use crate::wots::{WotsPublicKey, WotsSignature};

/// Configuration for Plonky2
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;
pub const D: usize = 2;

/// Errors that can occur during aggregate signature operations
#[derive(Error, Debug)]
pub enum AggregateError {
    #[error("Invalid signature at index {0}")]
    InvalidSignature(usize),
    
    #[error("Mismatched number of signatures and public keys")]
    MismatchedCount,
    
    #[error("Circuit construction failed: {0}")]
    CircuitError(String),
    
    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),
    
    #[error("Proof verification failed")]
    VerificationFailed,
    
    #[error("Invalid public inputs")]
    InvalidPublicInputs,
}

/// Bundle of signatures to be aggregated
#[derive(Debug, Clone)]
pub struct SignatureBundle {
    pub signatures: Vec<WotsSignature>,
    pub public_keys: Vec<WotsPublicKey>,
    pub message: Vec<u8>,
}

impl SignatureBundle {
    pub fn new(
        signatures: Vec<WotsSignature>,
        public_keys: Vec<WotsPublicKey>,
        message: Vec<u8>,
    ) -> Result<Self, AggregateError> {
        if signatures.len() != public_keys.len() {
            return Err(AggregateError::MismatchedCount);
        }
        
        Ok(Self {
            signatures,
            public_keys,
            message,
        })
    }
    
    pub fn len(&self) -> usize {
        self.signatures.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

/// Aggregated proof containing the ZK proof and public inputs
#[derive(Debug)]
pub struct AggregateProof {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub circuit_data: CircuitData<F, C, D>,
    pub num_signatures: usize,
}

/// Public inputs for the aggregate proof
#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub message_hash: Vec<F>,
    pub public_key_commitments: Vec<Vec<F>>,
}

impl PublicInputs {
    /// Convert public inputs to field elements for the circuit
    pub fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        
        // Add message hash
        elements.extend(&self.message_hash);
        
        // Add public key commitments
        for commitment in &self.public_key_commitments {
            elements.extend(commitment);
        }
        
        elements
    }
    
    /// Parse field elements back into public inputs
    pub fn from_field_elements(
        elements: &[F],
        num_signatures: usize,
        hash_size: usize,
    ) -> Result<Self, AggregateError> {
        let mut index = 0;
        
        // Extract message hash
        if elements.len() < hash_size {
            return Err(AggregateError::InvalidPublicInputs);
        }
        let message_hash = elements[index..index + hash_size].to_vec();
        index += hash_size;
        
        // Extract public key commitments
        let mut public_key_commitments = Vec::new();
        for _ in 0..num_signatures {
            if elements.len() < index + hash_size {
                return Err(AggregateError::InvalidPublicInputs);
            }
            let commitment = elements[index..index + hash_size].to_vec();
            public_key_commitments.push(commitment);
            index += hash_size;
        }
        
        Ok(Self {
            message_hash,
            public_key_commitments,
        })
    }
}