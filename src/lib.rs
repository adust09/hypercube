pub mod core;
pub mod crypto;
pub mod schemes;
pub mod wots;
pub mod xmss;

// Re-export main XMSS types for convenient external usage
pub use xmss::{
    AuthPath, MerkleTree, WOTSPlusParams, XMSSKeypair, XMSSParams, XMSSPrivateKey, XMSSPublicKey,
    XMSSSignature,
};
