use crate::xmss::tree::AuthPath;
use crate::xmss::core::XMSSParams;
use crate::wots::WotsSignature;

#[derive(Debug, Clone)]
pub struct XMSSSignature {
    leaf_index: usize,
    randomness: Vec<u8>,
    wots_signature: WotsSignature,
    auth_path: AuthPath,
}

impl XMSSSignature {
    pub fn new(
        leaf_index: usize,
        randomness: Vec<u8>,
        wots_signature: WotsSignature,
        auth_path: AuthPath,
    ) -> Self {
        assert_eq!(randomness.len(), 32, "Randomness must be 32 bytes");
        
        XMSSSignature {
            leaf_index,
            randomness,
            wots_signature,
            auth_path,
        }
    }

    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    pub fn randomness(&self) -> &[u8] {
        &self.randomness
    }

    pub fn wots_signature(&self) -> &WotsSignature {
        &self.wots_signature
    }

    pub fn auth_path(&self) -> &AuthPath {
        &self.auth_path
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        bytes.extend_from_slice(&(self.leaf_index as u32).to_be_bytes());
        
        bytes.extend_from_slice(&self.randomness);
        
        for chain in self.wots_signature.chains() {
            bytes.extend_from_slice(chain);
        }
        
        for node in self.auth_path.nodes() {
            bytes.extend_from_slice(node);
        }
        
        bytes
    }

    pub fn from_bytes(bytes: &[u8], _params: &XMSSParams) -> Result<Self, String> {
        if bytes.len() < 36 {
            return Err("Invalid signature length".to_string());
        }
        
        let mut offset = 0;
        
        let _leaf_index = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        
        let _randomness = bytes[offset..offset + 32].to_vec();
        let _ = offset + 32;
        
        Err("Not fully implemented".to_string())
    }
}