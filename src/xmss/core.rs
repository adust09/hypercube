use crate::crypto::hash::HashFunction;

#[derive(Debug, Clone)]
pub struct XMSSParams {
    tree_height: usize,
    winternitz_parameter: usize,
    len: usize,
    use_hypercube: bool,
}

impl XMSSParams {
    pub fn new(tree_height: usize, winternitz_parameter: usize, len: usize) -> Self {
        assert!(tree_height > 0, "Tree height must be positive");
        assert!(winternitz_parameter > 1, "Winternitz parameter must be > 1");
        assert!(len > 0, "Length must be positive");
        
        XMSSParams {
            tree_height,
            winternitz_parameter,
            len,
            use_hypercube: false,
        }
    }

    pub fn new_with_hypercube(tree_height: usize, security_bits: usize, use_hypercube: bool) -> Self {
        assert!(tree_height > 0, "Tree height must be positive");
        assert!(security_bits == 128 || security_bits == 160 || security_bits == 256, 
                "Security bits must be 128, 160, or 256");
        
        let (w, len) = if use_hypercube {
            // For hypercube with TSL, we need to match the actual TSL parameters
            use crate::schemes::tsl::{TSL, TSLConfig};
            use crate::core::encoding::EncodingScheme;
            let tsl = TSL::new(TSLConfig::new(security_bits));
            (tsl.alphabet_size(), tsl.dimension())
        } else {
            (67, 67)
        };
        
        XMSSParams {
            tree_height,
            winternitz_parameter: w,
            len,
            use_hypercube,
        }
    }

    pub fn tree_height(&self) -> usize {
        self.tree_height
    }

    pub fn winternitz_parameter(&self) -> usize {
        self.winternitz_parameter
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn total_tree_height(&self) -> usize {
        self.tree_height
    }

    pub fn use_hypercube(&self) -> bool {
        self.use_hypercube
    }
}

#[derive(Debug, Clone)]
pub struct XMSSPublicKey {
    root: Vec<u8>,
    public_seed: Vec<u8>,
}

impl XMSSPublicKey {
    pub fn new(root: Vec<u8>, public_seed: Vec<u8>) -> Self {
        assert_eq!(root.len(), 32, "Root must be 32 bytes");
        assert_eq!(public_seed.len(), 32, "Public seed must be 32 bytes");
        
        XMSSPublicKey {
            root,
            public_seed,
        }
    }

    pub fn root(&self) -> &[u8] {
        &self.root
    }

    pub fn public_seed(&self) -> &[u8] {
        &self.public_seed
    }

    pub fn verify(&self, message: &[u8], signature: &crate::xmss::signature::XMSSSignature, params: &XMSSParams) -> bool {
        use crate::crypto::hash::{HashFunction, SHA256};
        
        let hasher = SHA256::new();
        
        // Compute message hash
        let mut msg_data = Vec::new();
        msg_data.extend_from_slice(signature.randomness());
        msg_data.extend_from_slice(&self.root);
        msg_data.extend_from_slice(&(signature.leaf_index() as u32).to_be_bytes());
        msg_data.extend_from_slice(message);
        let message_digest = hasher.hash(&msg_data);
        
        // Compute leaf from WOTS signature with correct parameters
        let wots_pk_hash = compute_wots_public_key_hash_with_params(&message_digest, signature.wots_signature(), &hasher, params);
        
        // Verify authentication path
        let computed_root = signature.auth_path().compute_root(
            &wots_pk_hash,
            signature.leaf_index(),
            &self.public_seed,
            &hasher,
        );
        
        let result = computed_root == self.root;
        if !result {
            eprintln!("XMSS verify failed:");
            eprintln!("  Expected root: {:?}", &self.root[0..8]);
            eprintln!("  Computed root: {:?}", &computed_root[0..8]);
        }
        result
    }
}

#[derive(Debug, Clone)]
pub struct XMSSPrivateKey {
    leaf_index: usize,
    _wots_keys: Vec<Vec<u8>>,
    sk_seed: Vec<u8>,
    sk_prf: Vec<u8>,
    public_seed: Vec<u8>,
    root: Vec<u8>,
}

impl XMSSPrivateKey {
    pub fn new(
        leaf_index: usize,
        wots_keys: Vec<Vec<u8>>,
        sk_seed: Vec<u8>,
        sk_prf: Vec<u8>,
        public_seed: Vec<u8>,
        root: Vec<u8>,
    ) -> Self {
        assert_eq!(sk_seed.len(), 32, "SK seed must be 32 bytes");
        assert_eq!(sk_prf.len(), 32, "SK PRF must be 32 bytes");
        assert_eq!(public_seed.len(), 32, "Public seed must be 32 bytes");
        assert_eq!(root.len(), 32, "Root must be 32 bytes");
        
        XMSSPrivateKey {
            leaf_index,
            _wots_keys: wots_keys,
            sk_seed,
            sk_prf,
            public_seed,
            root,
        }
    }

    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    pub fn increment_leaf_index(&mut self) {
        self.leaf_index += 1;
    }

    pub fn sk_seed(&self) -> &[u8] {
        &self.sk_seed
    }

    pub fn sk_prf(&self) -> &[u8] {
        &self.sk_prf
    }

    pub fn public_seed(&self) -> &[u8] {
        &self.public_seed
    }

    pub fn root(&self) -> &[u8] {
        &self.root
    }

    pub fn export_state(&self) -> XMSSPrivateKeyState {
        XMSSPrivateKeyState {
            leaf_index: self.leaf_index,
            sk_seed: self.sk_seed.clone(),
            sk_prf: self.sk_prf.clone(),
            public_seed: self.public_seed.clone(),
            root: self.root.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct XMSSPrivateKeyState {
    pub leaf_index: usize,
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pub public_seed: Vec<u8>,
    pub root: Vec<u8>,
}

fn compute_wots_public_key_hash_with_params(
    message_digest: &[u8],
    wots_signature: &crate::wots::WotsSignature,
    hasher: &dyn HashFunction,
    params: &XMSSParams,
) -> Vec<u8> {
    use crate::wots::hash_chain;
    
    let w = params.winternitz_parameter();
    let chains = wots_signature.chains().len();
    
    let message_values = if params.use_hypercube() {
        // For hypercube encoding, apply the same TSL encoding as in signing
        use crate::schemes::tsl::{TSL, TSLConfig};
        use crate::core::encoding::EncodingScheme;
        
        // Use the same zero randomness as in signing
        let randomness = [0u8; 32];
        
        // Use the same TSL encoding as in signing
        let security_bits = match w {
            8 => 128,   // TSL uses w=8 for 128-bit security
            6 => 160,   
            4 => 256,
            _ => 128,
        };
        let tsl = TSL::new(TSLConfig::new(security_bits));
        let vertex = <TSL as EncodingScheme>::encode(&tsl, message_digest, &randomness);
        
        // Convert from [1, w] to [0, w-1] as done in signing
        vertex.components()
            .iter()
            .map(|&x| x.saturating_sub(1))
            .collect()
    } else {
        // Standard base-w encoding
        base_w_from_bytes(message_digest, w, chains)
    };
    
    // Reconstruct WOTS public key chains
    let mut pk_chains = Vec::new();
    for (i, sig_chain) in wots_signature.chains().iter().enumerate() {
        let x_i = message_values[i];
        let remaining_iterations = w - 1 - x_i;
        let pk_chain = hash_chain(hasher, sig_chain, remaining_iterations);
        pk_chains.push(pk_chain);
    }
    
    // Hash all chains together to get public key hash
    let mut data = Vec::new();
    for chain in &pk_chains {
        data.extend_from_slice(chain);
    }
    
    hasher.hash(&data)
}

fn base_w_from_bytes(bytes: &[u8], w: usize, out_len: usize) -> Vec<usize> {
    let mut result = Vec::with_capacity(out_len);
    let mut total = 0u64;
    let mut bits = 0;
    
    let log_w = (w as f64).log2() as u32;
    let w_mask = (1 << log_w) - 1;
    
    for &byte in bytes {
        total |= (byte as u64) << bits;
        bits += 8;
        
        while bits >= log_w && result.len() < out_len {
            result.push((total & w_mask) as usize);
            total >>= log_w;
            bits -= log_w;
        }
        
        if result.len() >= out_len {
            break;
        }
    }
    
    // If we need more values, pad with 0s
    while result.len() < out_len {
        if bits > 0 {
            result.push((total & w_mask) as usize);
            total >>= log_w;
            bits = bits.saturating_sub(log_w);
        } else {
            result.push(0);
        }
    }
    
    result
}