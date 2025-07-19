pub mod circuit;
pub mod prover;
pub mod verifier;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

/// Type aliases for Plonky2 configuration
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;
pub const D: usize = 2;