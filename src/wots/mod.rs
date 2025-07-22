// Winternitz One-Time Signature implementation
//
// This module implements the standard WOTS signature scheme that is
// integrated with the hypercube-based encoding schemes.

use crate::crypto::hash::{HashFunction, SHA256};
use crate::crypto::random::{OsSecureRandom, SecureRandom};

/// WOTS parameters
/// WOTS parameters derived from hypercube scheme
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
/// pk = (pk₁, ..., pkₗ) where pkᵢ = H^{w-1}(skᵢ)
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

    pub fn from_chains(chains: Vec<Vec<u8>>, params: WotsParams) -> Self {
        WotsPublicKey { chains, params }
    }

    /// Verify a signature
    /// Paper Algorithm WOTS-Verify: Verifies signature by checking
    /// if H^{w-1-xᵢ}(σᵢ) = pkᵢ for all i
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
            if x_i >= self.params.w {
                return false;
            }

            // Compute H^{w-1-xᵢ}(σᵢ) and check if it equals pkᵢ
            let iterations = self.params.w - 1 - x_i;
            let computed = hash_chain(&hasher, &signature.chains[i], iterations);

            if computed != self.chains[i] {
                return false;
            }
        }

        true
    }
}

/// WOTS secret key
/// sk = (sk₁, ..., skₗ) where each skᵢ is random
#[derive(Debug, Clone)]
pub struct WotsSecretKey {
    chains: Vec<Vec<u8>>,
}

impl WotsSecretKey {
    pub fn chains(&self) -> &[Vec<u8>] {
        &self.chains
    }

    pub fn from_chains(chains: Vec<Vec<u8>>) -> Self {
        WotsSecretKey { chains }
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

            // Paper: Compute public key pkᵢ = H^{w-1}(skᵢ)
            let pk_i = hash_chain(&hasher, &sk_i, params.w - 1);

            sk_chains.push(sk_i);
            pk_chains.push(pk_i);
        }

        WotsKeypair {
            public_key: WotsPublicKey {
                chains: pk_chains,
                params: params.clone(),
            },
            secret_key: WotsSecretKey { chains: sk_chains },
            params: params.clone(),
        }
    }

    pub fn from_components(
        public_key: WotsPublicKey,
        secret_key: WotsSecretKey,
        params: WotsParams,
    ) -> Self {
        WotsKeypair {
            public_key,
            secret_key,
            params,
        }
    }

    pub fn public_key(&self) -> &WotsPublicKey {
        &self.public_key
    }

    pub fn secret_key(&self) -> &WotsSecretKey {
        &self.secret_key
    }

    /// Sign a message with encoding
    /// Integration with hypercube encoding
    /// The encoding scheme maps the message to a vertex which provides
    /// the WOTS message digits
    pub fn sign<E: crate::core::encoding::EncodingScheme>(
        &self,
        message: &[u8],
        encoding: &E,
    ) -> WotsSignature {
        // For deterministic encoding, use zeros as randomness
        // The message itself provides the entropy
        let randomness = [0u8; 32];

        // Encode message to hypercube vertex
        let vertex = encoding.encode(message, &randomness);

        // The vertex components (a₁, ..., aᵥ) become WOTS message digits
        // Convert from hypercube range [1, w] to WOTS range [0, w-1]
        let message_digest: Vec<usize> = vertex
            .components()
            .iter()
            .map(|&x| x.saturating_sub(1))
            .collect();

        self.sign_raw(&message_digest)
    }

    /// Sign a message digest
    /// σᵢ = H^{xᵢ}(skᵢ) for each digit xᵢ
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
                x_i < self.params.w,
                "Message digit {} out of range [0, {})",
                x_i,
                self.params.w
            );

            // Compute σᵢ = H^{xᵢ}(skᵢ)
            let sig_i = hash_chain(&hasher, &self.secret_key.chains[i], x_i);
            sig_chains.push(sig_i);
        }

        WotsSignature { chains: sig_chains }
    }
}

/// WOTS signature
/// σ = (σ₁, ..., σₗ) where σᵢ = H^{xᵢ}(skᵢ)
#[derive(Debug, Clone)]
pub struct WotsSignature {
    chains: Vec<Vec<u8>>,
}

impl WotsSignature {
    pub fn chains(&self) -> &[Vec<u8>] {
        &self.chains
    }

    pub fn from_chains(chains: Vec<Vec<u8>>) -> Self {
        WotsSignature { chains }
    }
}

/// Compute hash chain H^k(x)
/// Hash chain computation H^k(x) = H(H(...H(x)...))
/// where H is applied k times. H^0(x) = x by definition.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wots_params() {
        // Test WOTS parameter creation
        let params = WotsParams::new(4, 64); // w=4, v=64

        assert_eq!(params.w(), 4);
        assert_eq!(params.chains(), 64);
        assert_eq!(params.max_hash_iterations(), 3); // w-1 = 3
    }

    #[test]
    fn test_wots_keygen() {
        let params = WotsParams::new(4, 8); // Small params for testing
        let keypair = WotsKeypair::generate(&params);

        // Check key sizes
        assert_eq!(keypair.public_key().chains().len(), 8);
        assert_eq!(keypair.secret_key().chains().len(), 8);

        // Verify public key is H^{w-1}(secret key)
        // This is checked internally, but we can verify the structure
        for i in 0..8 {
            assert_eq!(keypair.public_key().chains()[i].len(), 32); // SHA256 output
            assert_eq!(keypair.secret_key().chains()[i].len(), 32);
        }
    }

    #[test]
    fn test_wots_sign_verify() {
        let params = WotsParams::new(4, 8);
        let keypair = WotsKeypair::generate(&params);

        // Create a message digest (would come from encoding in real use)
        let message_digest = vec![1, 2, 0, 3, 1, 2, 0, 3]; // Values in [0,3] for w=4

        // Sign
        let signature = keypair.sign_raw(&message_digest);

        // Verify
        assert!(keypair.public_key().verify(&message_digest, &signature));
    }

    #[test]
    fn test_wots_wrong_message() {
        let params = WotsParams::new(4, 8);
        let keypair = WotsKeypair::generate(&params);

        let message_digest = vec![1, 2, 0, 3, 1, 2, 0, 3];
        let wrong_message = vec![0, 2, 0, 3, 1, 2, 0, 3]; // Changed first element

        let signature = keypair.sign_raw(&message_digest);

        // Verification should fail for wrong message
        assert!(!keypair.public_key().verify(&wrong_message, &signature));
    }

    #[test]
    fn test_wots_signature_size() {
        let params = WotsParams::new(4, 64);
        let keypair = WotsKeypair::generate(&params);

        let message_digest = vec![2; 64]; // All 2s
        let signature = keypair.sign_raw(&message_digest);

        // Signature should have 64 chains
        assert_eq!(signature.chains().len(), 64);

        // Each chain should be a hash value
        for chain in signature.chains() {
            assert_eq!(chain.len(), 32); // SHA256 output
        }
    }

    #[test]
    fn test_wots_hash_chain_computation() {
        let hasher = SHA256::new();
        let input = vec![0x42; 32]; // 32 bytes of 0x42

        // Test H^0(x) = x
        let h0 = hash_chain(&hasher, &input, 0);
        assert_eq!(h0, input);

        // Test H^1(x) = H(x)
        let h1 = hash_chain(&hasher, &input, 1);
        let expected_h1 = hasher.hash(&input);
        assert_eq!(h1, expected_h1);

        // Test H^3(x) = H(H(H(x)))
        let h3 = hash_chain(&hasher, &input, 3);
        let temp1 = hasher.hash(&input);
        let temp2 = hasher.hash(&temp1);
        let expected_h3 = hasher.hash(&temp2);
        assert_eq!(h3, expected_h3);
    }

    #[test]
    fn test_wots_deterministic_signing() {
        let params = WotsParams::new(4, 8);
        let keypair = WotsKeypair::generate(&params);

        let message_digest = vec![1, 2, 0, 3, 1, 2, 0, 3];

        // Same message should produce same signature
        let sig1 = keypair.sign_raw(&message_digest);
        let sig2 = keypair.sign_raw(&message_digest);

        assert_eq!(sig1.chains(), sig2.chains());
    }

    #[test]
    fn test_wots_security_property() {
        // Test one-time security property
        // If we sign two different messages with same key,
        // an attacker might be able to forge
        let params = WotsParams::new(4, 4); // Small for testing
        let keypair = WotsKeypair::generate(&params);

        let msg1 = vec![0, 1, 2, 3];
        let msg2 = vec![1, 2, 3, 0];

        let sig1 = keypair.sign_raw(&msg1);
        let sig2 = keypair.sign_raw(&msg2);

        // Both signatures should verify
        assert!(keypair.public_key().verify(&msg1, &sig1));
        assert!(keypair.public_key().verify(&msg2, &sig2));

        // But signing two messages reveals information
        // (In practice, this key should never be used again)
    }
}
