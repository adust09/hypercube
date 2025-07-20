use crate::wots::WotsSignature;
use crate::xmss::core::XMSSParams;
use crate::xmss::tree::AuthPath;

#[derive(Debug, Clone,)]
pub struct XMSSSignature {
    leaf_index: usize,
    randomness: Vec<u8,>,
    wots_signature: WotsSignature,
    auth_path: AuthPath,
}

impl XMSSSignature {
    pub fn new(
        leaf_index: usize,
        randomness: Vec<u8,>,
        wots_signature: WotsSignature,
        auth_path: AuthPath,
    ) -> Self {
        assert_eq!(randomness.len(), 32, "Randomness must be 32 bytes");

        XMSSSignature { leaf_index, randomness, wots_signature, auth_path, }
    }

    pub fn leaf_index(&self,) -> usize {
        self.leaf_index
    }

    pub fn randomness(&self,) -> &[u8] {
        &self.randomness
    }

    pub fn wots_signature(&self,) -> &WotsSignature {
        &self.wots_signature
    }

    pub fn auth_path(&self,) -> &AuthPath {
        &self.auth_path
    }

    pub fn to_bytes(&self,) -> Vec<u8,> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.leaf_index as u32).to_be_bytes(),);

        bytes.extend_from_slice(&self.randomness,);

        for chain in self.wots_signature.chains() {
            bytes.extend_from_slice(chain,);
        }

        for node in self.auth_path.nodes() {
            bytes.extend_from_slice(node,);
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8], params: &XMSSParams,) -> Result<Self, String,> {
        let hash_size = 32; // SHA256 output size
        let wots_chains = params.len(); // Number of WOTS chains
        let tree_height = params.tree_height();

        // Calculate expected size
        let expected_size = 4 + 32 + (wots_chains * hash_size) + (tree_height * hash_size);

        if bytes.len() != expected_size {
            return Err(format!(
                "Invalid signature length: expected {}, got {}",
                expected_size,
                bytes.len()
            ),);
        }

        let mut offset = 0;

        // Parse leaf index
        let leaf_index = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ],) as usize;
        offset += 4;

        // Parse randomness
        let randomness = bytes[offset..offset + 32].to_vec();
        offset += 32;

        // Parse WOTS signature chains
        let mut wots_chains = Vec::with_capacity(wots_chains,);
        for _ in 0..params.len() {
            let chain = bytes[offset..offset + hash_size].to_vec();
            wots_chains.push(chain,);
            offset += hash_size;
        }
        let wots_signature = crate::wots::WotsSignature::from_chains(wots_chains,);

        // Parse authentication path nodes
        let mut auth_nodes = Vec::with_capacity(tree_height,);
        for _ in 0..tree_height {
            let node = bytes[offset..offset + hash_size].to_vec();
            auth_nodes.push(node,);
            offset += hash_size;
        }
        let auth_path = AuthPath::new(auth_nodes,);

        Ok(XMSSSignature { leaf_index, randomness, wots_signature, auth_path, },)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmss::{XMSSKeypair, XMSSParams};

    #[test]
    fn test_xmss_signature_serialization() {
        let params = XMSSParams::new(4, 67, 16,);
        let mut keypair = XMSSKeypair::generate(&params,);
        let message = b"Test message";

        let signature = keypair.sign(message,);
        let serialized = signature.to_bytes();
        let deserialized = XMSSSignature::from_bytes(&serialized, &params,).unwrap();

        assert!(keypair.public_key().verify(message, &deserialized, keypair.params()));
    }

    #[test]
    fn test_xmss_signature_components() {
        let params = XMSSParams::new(4, 67, 16,);
        let mut keypair = XMSSKeypair::generate(&params,);
        let message = b"Component test";

        let signature = keypair.sign(message,);

        assert_eq!(signature.leaf_index(), 0);
        assert_eq!(signature.randomness().len(), 32);
        assert_eq!(signature.auth_path().nodes().len(), 4);
        assert!(signature.wots_signature().chains().len() > 0);
    }
}
