use crate::xmss::core::{XMSSParams, XMSSPublicKey, XMSSPrivateKey, XMSSPrivateKeyState};
use crate::xmss::tree::MerkleTree;
use crate::xmss::signature::XMSSSignature;
use crate::xmss::wots_plus::WOTSPlusParams;
use crate::crypto::hash::{HashFunction, SHA256};
use crate::crypto::random::{OsSecureRandom, SecureRandom};

pub struct XMSSKeypair {
    public_key: XMSSPublicKey,
    private_key: XMSSPrivateKey,
    params: XMSSParams,
}

impl XMSSKeypair {
    pub fn generate(params: &XMSSParams) -> Self {
        let mut rng = OsSecureRandom::new();
        let seed = rng.random_bytes(96);  // 32 + 32 + 32
        
        Self::generate_from_seed(params, &seed)
    }

    pub fn generate_from_seed(params: &XMSSParams, seed: &[u8]) -> Self {
        assert_eq!(seed.len(), 96, "Seed must be 96 bytes");
        
        let sk_seed = seed[0..32].to_vec();
        let sk_prf = seed[32..64].to_vec();
        let public_seed = seed[64..96].to_vec();
        
        let hasher = SHA256::new();
        let num_leaves = 1 << params.tree_height();
        let mut leaves = Vec::with_capacity(num_leaves);
        let wots_params = WOTSPlusParams::from_xmss_params(params);
        
        for i in 0..num_leaves {
            let address = (i as u32).to_be_bytes();
            let keypair = wots_params.generate_keypair(&sk_seed, &address);
            leaves.push(keypair.public_key_hash());
        }
        
        let tree = MerkleTree::build(&leaves, &public_seed, &hasher);
        let root = tree.root().to_vec();
        
        let public_key = XMSSPublicKey::new(root.clone(), public_seed.clone());
        let private_key = XMSSPrivateKey::new(
            0,
            vec![],
            sk_seed,
            sk_prf,
            public_seed,
            root,
        );
        
        XMSSKeypair {
            public_key,
            private_key,
            params: params.clone(),
        }
    }

    pub fn public_key(&self) -> &XMSSPublicKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &XMSSPrivateKey {
        &self.private_key
    }

    pub fn sign(&mut self, message: &[u8]) -> XMSSSignature {
        let leaf_idx = self.private_key.leaf_index();
        let max_signatures = 1 << self.params.tree_height();
        
        if leaf_idx >= max_signatures {
            panic!("XMSS key exhausted");
        }
        
        let hasher = SHA256::new();
        
        // Compute PRF(SK_PRF, idx_sig || M)
        let mut r_data = Vec::new();
        r_data.extend_from_slice(self.private_key.sk_prf());
        r_data.extend_from_slice(&(leaf_idx as u32).to_be_bytes());
        r_data.extend_from_slice(message);
        let randomness = hasher.hash(&r_data);
        
        // Hash(r || root || idx_sig || M)
        let mut msg_data = Vec::new();
        msg_data.extend_from_slice(&randomness);
        msg_data.extend_from_slice(self.private_key.root());
        msg_data.extend_from_slice(&(leaf_idx as u32).to_be_bytes());
        msg_data.extend_from_slice(message);
        let message_digest = hasher.hash(&msg_data);
        
        let wots_params = WOTSPlusParams::from_xmss_params(&self.params);
        let address = (leaf_idx as u32).to_be_bytes();
        let wots_keypair = wots_params.generate_keypair(self.private_key.sk_seed(), &address);
        let wots_signature = wots_keypair.sign(&message_digest);
        
        let num_leaves = 1 << self.params.tree_height();
        let mut leaves = Vec::with_capacity(num_leaves);
        
        for i in 0..num_leaves {
            let addr = (i as u32).to_be_bytes();
            let kp = wots_params.generate_keypair(self.private_key.sk_seed(), &addr);
            leaves.push(kp.public_key_hash());
        }
        
        let tree = MerkleTree::build(&leaves, self.private_key.public_seed(), &hasher);
        let auth_path = tree.authentication_path(leaf_idx);
        
        self.private_key.increment_leaf_index();
        
        XMSSSignature::new(leaf_idx, randomness, wots_signature, auth_path)
    }

    pub fn restore(params: &XMSSParams, state: XMSSPrivateKeyState) -> Self {
        let public_key = XMSSPublicKey::new(state.root.clone(), state.public_seed.clone());
        let private_key = XMSSPrivateKey::new(
            state.leaf_index,
            vec![],
            state.sk_seed,
            state.sk_prf,
            state.public_seed,
            state.root,
        );
        
        XMSSKeypair {
            public_key,
            private_key,
            params: params.clone(),
        }
    }
}