use crate::crypto::hash::HashFunction;
use crate::crypto::poseidon2::{Poseidon2Hash, poseidon2_hash_chain};
use crate::crypto::random::{OsSecureRandom, SecureRandom};
use crate::wots_poseidon::{
    WotsPoseidon2Params, WotsPoseidon2PublicKey, WotsPoseidon2SecretKey, WotsPoseidon2Signature
};

/// WOTS keypair using Poseidon2
pub struct WotsPoseidon2Keypair {
    pub public_key: WotsPoseidon2PublicKey,
    pub secret_key: WotsPoseidon2SecretKey,
    pub params: WotsPoseidon2Params,
}

impl WotsPoseidon2Keypair {
    /// Generate a new keypair using Poseidon2
    pub fn generate(params: &WotsPoseidon2Params) -> Self {
        let mut rng = OsSecureRandom::new();
        let hasher = Poseidon2Hash::new();
        
        let mut sk_chains = Vec::with_capacity(params.chains);
        let mut pk_chains = Vec::with_capacity(params.chains);
        
        // Generate each chain
        for _ in 0..params.chains {
            // Generate random secret key
            let sk_i = rng.random_bytes(hasher.output_size());
            
            // Compute public key as H^{w-1}(sk_i) using Poseidon2
            let pk_i = poseidon2_hash_chain(&sk_i, params.w - 1);
            
            sk_chains.push(sk_i);
            pk_chains.push(pk_i);
        }
        
        Self {
            public_key: WotsPoseidon2PublicKey {
                chains: pk_chains,
                params: params.clone(),
            },
            secret_key: WotsPoseidon2SecretKey { chains: sk_chains },
            params: params.clone(),
        }
    }
    
    /// Sign a message digest
    pub fn sign(&self, message_digest: &[usize]) -> WotsPoseidon2Signature {
        assert_eq!(
            message_digest.len(),
            self.params.chains,
            "Message digest length must match number of chains"
        );
        
        let mut sig_chains = Vec::with_capacity(self.params.chains);
        
        for i in 0..self.params.chains {
            let x_i = message_digest[i];
            assert!(
                x_i >= 1 && x_i <= self.params.w,
                "Message digit {} out of range [1, {}]",
                x_i,
                self.params.w
            );
            
            // Compute σ_i = H^{x_i-1}(sk_i) using Poseidon2
            let sig_i = poseidon2_hash_chain(&self.secret_key.chains[i], x_i - 1);
            sig_chains.push(sig_i);
        }
        
        WotsPoseidon2Signature { chains: sig_chains }
    }
    
    /// Verify a signature
    pub fn verify(&self, message_digest: &[usize], signature: &WotsPoseidon2Signature) -> bool {
        if message_digest.len() != self.params.chains {
            return false;
        }
        
        if signature.chains.len() != self.params.chains {
            return false;
        }
        
        // Check each chain
        for i in 0..self.params.chains {
            let x_i = message_digest[i];
            if x_i < 1 || x_i > self.params.w {
                return false;
            }
            
            // Compute H^{w-x_i}(σ_i) using Poseidon2
            let iterations = self.params.w - x_i;
            let computed = poseidon2_hash_chain(&signature.chains[i], iterations);
            
            if computed != self.public_key.chains[i] {
                return false;
            }
        }
        
        true
    }
    
    pub fn public_key(&self) -> &WotsPoseidon2PublicKey {
        &self.public_key
    }
    
    pub fn secret_key(&self) -> &WotsPoseidon2SecretKey {
        &self.secret_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_poseidon2_keypair_generation() {
        let params = WotsPoseidon2Params::new(16, 32);
        let keypair = WotsPoseidon2Keypair::generate(&params);
        
        assert_eq!(keypair.public_key.chains.len(), 32);
        assert_eq!(keypair.secret_key.chains.len(), 32);
    }
    
    #[test]
    fn test_poseidon2_sign_verify() {
        let params = WotsPoseidon2Params::new(16, 32);
        let keypair = WotsPoseidon2Keypair::generate(&params);
        
        // Create a message digest
        let message_digest: Vec<usize> = (1..=32).map(|i| (i % 15) + 1).collect();
        
        // Sign the message
        let signature = keypair.sign(&message_digest);
        
        // Verify the signature
        assert!(keypair.verify(&message_digest, &signature));
        
        // Verify with wrong message fails
        let wrong_digest: Vec<usize> = (1..=32).map(|i| ((i + 1) % 15) + 1).collect();
        assert!(!keypair.verify(&wrong_digest, &signature));
    }
}