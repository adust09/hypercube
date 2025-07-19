// Winternitz One-Time Signature implementation

use crate::crypto::hash::{HashFunction, SHA256};
use crate::crypto::random::{OsSecureRandom, SecureRandom};

/// WOTS parameters
#[derive(Debug, Clone)]
pub struct WotsParams {
    w: usize,
    chains: usize,
}

impl WotsParams {
    pub fn new(w: usize, chains: usize) -> Self {
        assert!(w > 1, "w must be greater than 1");
        assert!(chains > 0, "chains must be positive");
        WotsParams { w, chains }
    }

    pub fn w(&self) -> usize {
        self.w
    }

    pub fn chains(&self) -> usize {
        self.chains
    }

    pub fn max_hash_iterations(&self) -> usize {
        self.w - 1
    }
}

/// WOTS public key
#[derive(Debug, Clone)]
pub struct WotsPublicKey {
    chains: Vec<Vec<u8>>,
    params: WotsParams,
}

impl WotsPublicKey {
    pub fn chains(&self) -> &[Vec<u8>] {
        &self.chains
    }

    pub fn params(&self) -> &WotsParams {
        &self.params
    }

    /// Verify a signature
    pub fn verify(&self, message_digest: &[usize], signature: &WotsSignature) -> bool {
        if message_digest.len() != self.params.chains {
            return false;
        }

        if signature.chains.len() != self.params.chains {
            return false;
        }

        // Check each chain
        let hasher = SHA256::new();
        for i in 0..self.params.chains {
            let x_i = message_digest[i];
            if x_i < 1 || x_i > self.params.w {
                return false;
            }

            // Compute H^{w-x_i}(σ_i)
            let iterations = self.params.w - x_i;
            let computed = hash_chain(&hasher, &signature.chains[i], iterations);

            if computed != self.chains[i] {
                return false;
            }
        }

        true
    }
}

/// WOTS secret key
#[derive(Debug, Clone)]
pub struct WotsSecretKey {
    chains: Vec<Vec<u8>>,
}

impl WotsSecretKey {
    pub fn chains(&self) -> &[Vec<u8>] {
        &self.chains
    }
}

/// WOTS keypair
pub struct WotsKeypair {
    public_key: WotsPublicKey,
    secret_key: WotsSecretKey,
    params: WotsParams,
}

impl WotsKeypair {
    /// Generate a new keypair
    pub fn generate(params: &WotsParams) -> Self {
        let mut rng = OsSecureRandom::new();
        let hasher = SHA256::new();

        let mut sk_chains = Vec::with_capacity(params.chains);
        let mut pk_chains = Vec::with_capacity(params.chains);

        // Generate each chain
        for _ in 0..params.chains {
            // Generate random secret key
            let sk_i = rng.random_bytes(hasher.output_size());

            // Compute public key as H^{w-1}(sk_i)
            let pk_i = hash_chain(&hasher, &sk_i, params.w - 1);

            sk_chains.push(sk_i);
            pk_chains.push(pk_i);
        }

        WotsKeypair {
            public_key: WotsPublicKey { chains: pk_chains, params: params.clone() },
            secret_key: WotsSecretKey { chains: sk_chains },
            params: params.clone(),
        }
    }

    pub fn public_key(&self) -> &WotsPublicKey {
        &self.public_key
    }

    pub fn secret_key(&self) -> &WotsSecretKey {
        &self.secret_key
    }

    /// Sign a message with encoding
    pub fn sign<E: crate::core::encoding::EncodingScheme>(&self, message: &[u8], encoding: &E) -> WotsSignature {
        use crate::crypto::random::{OsSecureRandom, SecureRandom};
        
        // Generate randomness
        let mut rng = OsSecureRandom::new();
        let randomness = rng.random_bytes(32);
        
        // Encode message to hypercube vertex
        let vertex = encoding.encode(message, &randomness);
        
        // Get message digits - the vertex components are the message digest
        let message_digest: Vec<usize> = vertex.components().clone();
        
        self.sign_raw(&message_digest)
    }

    /// Sign a message digest
    pub fn sign_raw(&self, message_digest: &[usize]) -> WotsSignature {
        assert_eq!(
            message_digest.len(),
            self.params.chains,
            "Message digest length must match number of chains"
        );

        let hasher = SHA256::new();
        let mut sig_chains = Vec::with_capacity(self.params.chains);

        for i in 0..self.params.chains {
            let x_i = message_digest[i];
            assert!(
                x_i >= 1 && x_i <= self.params.w,
                "Message digit {} out of range [1, {}]",
                x_i,
                self.params.w
            );

            // Compute σ_i = H^{x_i-1}(sk_i)
            let sig_i = hash_chain(&hasher, &self.secret_key.chains[i], x_i - 1);
            sig_chains.push(sig_i);
        }

        WotsSignature { chains: sig_chains }
    }
}

/// WOTS signature
#[derive(Debug, Clone)]
pub struct WotsSignature {
    chains: Vec<Vec<u8>>,
}

impl WotsSignature {
    pub fn chains(&self) -> &[Vec<u8>] {
        &self.chains
    }
}

/// Compute hash chain H^k(x)
pub fn hash_chain(hasher: &dyn HashFunction, input: &[u8], iterations: usize) -> Vec<u8> {
    if iterations == 0 {
        return input.to_vec();
    }

    let mut result = input.to_vec();
    for _ in 0..iterations {
        result = hasher.hash(&result);
    }
    result
}
