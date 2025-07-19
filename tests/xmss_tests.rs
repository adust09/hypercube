#[cfg(test)]
mod xmss_tests {
    use hypercube_signatures::xmss::{
        XMSSParams, XMSSKeypair,
        XMSSSignature, MerkleTree,
    };
    use hypercube_signatures::crypto::hash::{SHA256, HashFunction};

    #[test]
    fn test_xmss_params_creation() {
        let params = XMSSParams::new(10, 67, 16);
        assert_eq!(params.tree_height(), 10);
        assert_eq!(params.winternitz_parameter(), 67);
        assert_eq!(params.len(), 16);
        assert_eq!(params.total_tree_height(), 10);
    }

    #[test]
    fn test_xmss_keypair_generation() {
        let params = XMSSParams::new(4, 67, 16);
        let keypair = XMSSKeypair::generate(&params);
        
        assert_eq!(keypair.private_key().leaf_index(), 0);
        assert_eq!(keypair.public_key().root().len(), 32);
        assert_eq!(keypair.public_key().public_seed().len(), 32);
    }

    #[test]
    fn test_merkle_tree_construction() {
        let params = XMSSParams::new(3, 67, 16);
        let num_leaves = 1 << params.tree_height();
        let mut leaves = Vec::new();
        
        for i in 0..num_leaves {
            let leaf_data = format!("leaf_{}", i);
            leaves.push(SHA256::new().hash(leaf_data.as_bytes()));
        }
        
        let tree = MerkleTree::build(&leaves, &[0u8; 32], &SHA256::new());
        assert_eq!(tree.root().len(), 32);
        assert_eq!(tree.height(), 3);
    }

    #[test]
    fn test_authentication_path_generation() {
        let params = XMSSParams::new(3, 67, 16);
        let num_leaves = 1 << params.tree_height();
        let mut leaves = Vec::new();
        
        for i in 0..num_leaves {
            let leaf_data = format!("leaf_{}", i);
            leaves.push(SHA256::new().hash(leaf_data.as_bytes()));
        }
        
        let tree = MerkleTree::build(&leaves, &[0u8; 32], &SHA256::new());
        let auth_path = tree.authentication_path(0);
        
        assert_eq!(auth_path.nodes().len(), 3);
    }

    #[test]
    fn test_authentication_path_verification() {
        let params = XMSSParams::new(3, 67, 16);
        let num_leaves = 1 << params.tree_height();
        let mut leaves = Vec::new();
        let hasher = SHA256::new();
        
        for i in 0..num_leaves {
            let leaf_data = format!("leaf_{}", i);
            leaves.push(hasher.hash(leaf_data.as_bytes()));
        }
        
        let public_seed = [0u8; 32];
        let tree = MerkleTree::build(&leaves, &public_seed, &hasher);
        
        for leaf_idx in 0..num_leaves {
            let auth_path = tree.authentication_path(leaf_idx);
            let computed_root = auth_path.compute_root(
                &leaves[leaf_idx],
                leaf_idx,
                &public_seed,
                &hasher
            );
            assert_eq!(computed_root, tree.root());
        }
    }

    #[test]
    fn test_xmss_sign_and_verify_single_message() {
        let params = XMSSParams::new(4, 67, 16);
        let mut keypair = XMSSKeypair::generate(&params);
        let message = b"Hello, XMSS!";
        
        let signature = keypair.sign(message);
        assert!(keypair.public_key().verify(message, &signature));
        
        assert_eq!(keypair.private_key().leaf_index(), 1);
    }

    #[test]
    fn test_xmss_sign_multiple_messages() {
        let params = XMSSParams::new(4, 67, 16);
        let mut keypair = XMSSKeypair::generate(&params);
        let max_signatures = 1 << params.tree_height();
        
        for i in 0..max_signatures {
            let message = format!("Message {}", i);
            let signature = keypair.sign(message.as_bytes());
            assert!(keypair.public_key().verify(message.as_bytes(), &signature));
            assert_eq!(keypair.private_key().leaf_index(), i + 1);
        }
    }

    #[test]
    #[should_panic(expected = "XMSS key exhausted")]
    fn test_xmss_key_exhaustion() {
        let params = XMSSParams::new(2, 67, 16);
        let mut keypair = XMSSKeypair::generate(&params);
        let max_signatures = 1 << params.tree_height();
        
        for i in 0..=max_signatures {
            let message = format!("Message {}", i);
            keypair.sign(message.as_bytes());
        }
    }

    #[test]
    fn test_xmss_signature_serialization() {
        let params = XMSSParams::new(4, 67, 16);
        let mut keypair = XMSSKeypair::generate(&params);
        let message = b"Test message";
        
        let signature = keypair.sign(message);
        let serialized = signature.to_bytes();
        let deserialized = XMSSSignature::from_bytes(&serialized, &params).unwrap();
        
        assert!(keypair.public_key().verify(message, &deserialized));
    }

    #[test]
    fn test_xmss_with_different_tree_heights() {
        let heights = vec![2, 3, 4, 5, 10];
        
        for h in heights {
            let params = XMSSParams::new(h, 67, 16);
            let mut keypair = XMSSKeypair::generate(&params);
            let message = format!("Test with height {}", h);
            
            let signature = keypair.sign(message.as_bytes());
            assert!(keypair.public_key().verify(message.as_bytes(), &signature));
        }
    }

    #[test]
    fn test_xmss_signature_components() {
        let params = XMSSParams::new(4, 67, 16);
        let mut keypair = XMSSKeypair::generate(&params);
        let message = b"Component test";
        
        let signature = keypair.sign(message);
        
        assert_eq!(signature.leaf_index(), 0);
        assert_eq!(signature.randomness().len(), 32);
        assert_eq!(signature.auth_path().nodes().len(), 4);
        assert!(signature.wots_signature().chains().len() > 0);
    }

    #[test]
    fn test_xmss_deterministic_key_generation() {
        let params = XMSSParams::new(4, 67, 16);
        let seed = [42u8; 96];
        
        let keypair1 = XMSSKeypair::generate_from_seed(&params, &seed);
        let keypair2 = XMSSKeypair::generate_from_seed(&params, &seed);
        
        assert_eq!(
            keypair1.public_key().root(),
            keypair2.public_key().root()
        );
        assert_eq!(
            keypair1.public_key().public_seed(),
            keypair2.public_key().public_seed()
        );
    }

    #[test]
    fn test_xmss_hypercube_wots_integration() {
        let params = XMSSParams::new_with_hypercube(4, 128, true);
        let mut keypair = XMSSKeypair::generate(&params);
        let message = b"Hypercube optimized XMSS";
        
        let signature = keypair.sign(message);
        assert!(keypair.public_key().verify(message, &signature));
        
        let wots_chains = signature.wots_signature().chains().len();
        assert!(wots_chains < 67);
    }

    #[test]
    fn test_xmss_state_persistence() {
        let params = XMSSParams::new(4, 67, 16);
        let mut keypair = XMSSKeypair::generate(&params);
        
        keypair.sign(b"Message 1");
        keypair.sign(b"Message 2");
        
        let state = keypair.private_key().export_state();
        let mut restored_keypair = XMSSKeypair::restore(&params, state);
        
        assert_eq!(restored_keypair.private_key().leaf_index(), 2);
        
        let signature = restored_keypair.sign(b"Message 3");
        assert!(restored_keypair.public_key().verify(b"Message 3", &signature));
    }
}