use crate::crypto::hash::{HashFunction, SHA256};
use crate::schemes::tl1c::TL1C;
use crate::schemes::tlfc::TLFC;
use crate::schemes::tsl::{TSLConfig, TSL};
use crate::wots::{WotsKeypair, WotsParams, WotsSignature};
use crate::xmss::core::XMSSParams;

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

    pub fn generate_keypair(&self, seed: &[u8], address: &[u8]) -> WOTSPlusKeypair {
        // Always generate deterministic keypair with the inner params
        let keypair = Self::generate_deterministic_keypair(&self.inner_params, seed, address);

        if self.use_hypercube {
            let tsl = TSL::new(TSLConfig::new(self.security_bits));
            WOTSPlusKeypair {
                keypair,
                scheme: HypercubeScheme::TSL(tsl),
            }
        } else {
            WOTSPlusKeypair {
                keypair,
                scheme: HypercubeScheme::None,
            }
        }
    }

    fn generate_deterministic_keypair(
        params: &WotsParams,
        seed: &[u8],
        address: &[u8],
    ) -> WotsKeypair {
        let hasher = SHA256::new();
        let mut sk_chains = Vec::with_capacity(params.chains());
        let mut pk_chains = Vec::with_capacity(params.chains());

        // Generate each chain deterministically
        for i in 0..params.chains() {
            // PRF(seed || address || chain_index)
            let mut prf_input = Vec::new();
            prf_input.extend_from_slice(seed);
            prf_input.extend_from_slice(address);
            prf_input.extend_from_slice(&(i as u32).to_be_bytes());

            // Generate secret key for this chain
            let sk_i = hasher.hash(&prf_input);

            // Compute public key as H^{w-1}(sk_i)
            let pk_i = crate::wots::hash_chain(&hasher, &sk_i, params.w() - 1);

            sk_chains.push(sk_i);
            pk_chains.push(pk_i);
        }

        WotsKeypair::from_components(
            crate::wots::WotsPublicKey::from_chains(pk_chains, params.clone()),
            crate::wots::WotsSecretKey::from_chains(sk_chains),
            params.clone(),
        )
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
            HypercubeScheme::TSL(tsl) => self.keypair.sign(message_digest, tsl),
            HypercubeScheme::TL1C(tl1c) => self.keypair.sign(message_digest, tl1c),
            HypercubeScheme::TLFC(tlfc) => self.keypair.sign(message_digest, tlfc),
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
            result.push((total & w_mask) as usize);
            total >>= log_w;
            bits -= log_w;
        }

        _consumed += 1;
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
