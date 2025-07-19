pub mod keypair;

use crate::wots::WotsParams;

/// WOTS parameters for Poseidon2
#[derive(Debug, Clone)]
pub struct WotsPoseidon2Params {
    pub w: usize,
    pub chains: usize,
}

impl WotsPoseidon2Params {
    pub fn new(w: usize, chains: usize) -> Self {
        assert!(w > 1, "w must be greater than 1");
        assert!(chains > 0, "chains must be positive");
        Self { w, chains }
    }
    
    pub fn from_wots_params(params: &WotsParams) -> Self {
        Self {
            w: params.w(),
            chains: params.chains(),
        }
    }
}

/// WOTS public key for Poseidon2
#[derive(Debug, Clone)]
pub struct WotsPoseidon2PublicKey {
    pub chains: Vec<Vec<u8>>,
    pub params: WotsPoseidon2Params,
}

impl WotsPoseidon2PublicKey {
    pub fn chains(&self) -> &[Vec<u8>] {
        &self.chains
    }
}

/// WOTS secret key for Poseidon2
#[derive(Debug, Clone)]
pub struct WotsPoseidon2SecretKey {
    pub chains: Vec<Vec<u8>>,
}

impl WotsPoseidon2SecretKey {
    pub fn chains(&self) -> &[Vec<u8>] {
        &self.chains
    }
}

/// WOTS signature for Poseidon2
#[derive(Debug, Clone)]
pub struct WotsPoseidon2Signature {
    pub chains: Vec<Vec<u8>>,
}

impl WotsPoseidon2Signature {
    pub fn chains(&self) -> &[Vec<u8>] {
        &self.chains
    }
}

/// Convert existing WOTS signature to Poseidon2 format
impl From<&crate::wots::WotsSignature> for WotsPoseidon2Signature {
    fn from(sig: &crate::wots::WotsSignature) -> Self {
        Self {
            chains: sig.chains().to_vec(),
        }
    }
}

/// Convert existing WOTS public key to Poseidon2 format
impl From<&crate::wots::WotsPublicKey> for WotsPoseidon2PublicKey {
    fn from(pk: &crate::wots::WotsPublicKey) -> Self {
        // Note: This is a conversion, not a re-computation with Poseidon2
        // For true Poseidon2 keys, use WotsPoseidon2Keypair::generate
        Self {
            chains: pk.chains().to_vec(),
            params: WotsPoseidon2Params::new(16, pk.chains().len()), // Default w=16
        }
    }
}