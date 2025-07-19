use crate::crypto::hash::{HashFunction, SHA256};
use crate::wots::{WotsParams, WotsKeypair, WotsSignature};
use crate::schemes::tsl::{TSL, TSLConfig};
use crate::schemes::tl1c::TL1C;
use crate::schemes::tlfc::TLFC;
use crate::xmss::core::XMSSParams;
use crate::core::encoding::EncodingScheme;

#[derive(Debug, Clone)]
pub struct WOTSPlusParams {
    inner_params: WotsParams,
    use_hypercube: bool,
    security_bits: usize,
}

impl WOTSPlusParams {
    pub fn from_xmss_params(xmss_params: &XMSSParams) -> Self {
        let inner_params = if xmss_params.use_hypercube() {
            match xmss_params.winternitz_parameter() {
                64 => WotsParams::new(64, 64),
                80 => WotsParams::new(80, 80),
                128 => WotsParams::new(128, 128),
                _ => WotsParams::new(xmss_params.winternitz_parameter(), xmss_params.len()),
            }
        } else {
            WotsParams::new(xmss_params.winternitz_parameter(), xmss_params.len())
        };
        
        WOTSPlusParams {
            inner_params,
            use_hypercube: xmss_params.use_hypercube(),
            security_bits: match xmss_params.winternitz_parameter() {
                64 => 128,
                80 => 160,
                128 => 256,
                _ => 128,
            },
        }
    }

    pub fn inner_params(&self) -> &WotsParams {
        &self.inner_params
    }

    pub fn generate_keypair(&self, _seed: &[u8], _address: &[u8]) -> WOTSPlusKeypair {
        if self.use_hypercube {
            let tsl = TSL::new(TSLConfig::new(self.security_bits));
            // TSL has w and v dimensions
            let wots_params = WotsParams::new(tsl.alphabet_size(), tsl.dimension());
            let keypair = WotsKeypair::generate(&wots_params);
            
            WOTSPlusKeypair {
                keypair,
                scheme: HypercubeScheme::TSL(tsl),
            }
        } else {
            let keypair = WotsKeypair::generate(&self.inner_params);
            WOTSPlusKeypair {
                keypair,
                scheme: HypercubeScheme::None,
            }
        }
    }
}

pub struct WOTSPlusKeypair {
    keypair: WotsKeypair,
    scheme: HypercubeScheme,
}

enum HypercubeScheme {
    None,
    TSL(TSL),
    TL1C(TL1C),
    TLFC(TLFC),
}

impl WOTSPlusKeypair {
    pub fn sign(&self, message_digest: &[u8]) -> WotsSignature {
        match &self.scheme {
            HypercubeScheme::None => {
                // Convert hash to base-w representation
                let w = self.keypair.public_key().params().w();
                let chains = self.keypair.public_key().params().chains();
                let digest_values = base_w_from_bytes(message_digest, w, chains);
                self.keypair.sign_raw(&digest_values)
            }
            HypercubeScheme::TSL(tsl) => {
                self.keypair.sign(message_digest, tsl)
            }
            HypercubeScheme::TL1C(tl1c) => {
                self.keypair.sign(message_digest, tl1c)
            }
            HypercubeScheme::TLFC(tlfc) => {
                self.keypair.sign(message_digest, tlfc)
            }
        }
    }

    pub fn public_key_hash(&self) -> Vec<u8> {
        let hasher = SHA256::new();
        let mut data = Vec::new();
        
        for chain in self.keypair.public_key().chains() {
            data.extend_from_slice(chain);
        }
        
        hasher.hash(&data)
    }
}

fn base_w_from_bytes(bytes: &[u8], w: usize, out_len: usize) -> Vec<usize> {
    let mut result = Vec::with_capacity(out_len);
    let mut total = 0u64;
    let mut bits = 0;
    let mut _consumed = 0;
    
    let log_w = (w as f64).log2() as u32;
    let w_mask = (1 << log_w) - 1;
    
    for &byte in bytes {
        total |= (byte as u64) << bits;
        bits += 8;
        
        while bits >= log_w && result.len() < out_len {
            result.push(((total & w_mask) + 1) as usize);
            total >>= log_w;
            bits -= log_w;
        }
        
        _consumed += 1;
        if result.len() >= out_len {
            break;
        }
    }
    
    // If we need more values, pad with 1s
    while result.len() < out_len {
        if bits > 0 {
            result.push(((total & w_mask) + 1) as usize);
            total >>= log_w;
            bits = bits.saturating_sub(log_w);
        } else {
            result.push(1);
        }
    }
    
    result
}