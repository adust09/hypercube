# Hypercube-based-xmss

A Rust implementation of [At the Top of the Hypercube](https://eprint.iacr.org/2025/889.pdf) by Khovratovich et al.
And XMSS with TSL, which introduced in hypercube.

## Building

```bash
# Build in release mode
cargo build --release

# Run all tests
cargo test

# Run benchmarks
cargo bench
```

## Using as an External Crate

### Adding the Dependency

Add the following to your `Cargo.toml`:

```toml
[dependencies]
hypercube-signatures = { git = "https://github.com/ts21/hypercube" }
```

Or if you want to use a specific branch or commit:

```toml
[dependencies]
hypercube-signatures = { git = "https://github.com/ts21/hypercube", branch = "main" }
```

### Basic Usage

```rust
use hypercube_signatures::{XMSSParams, XMSSKeypair};

fn main() {
    // Create XMSS parameters
    // Parameters: (tree_height, winternitz_parameter, len)
    let params = XMSSParams::new(10, 67, 16);
    
    // Generate a keypair
    let mut keypair = XMSSKeypair::generate(&params);
    
    // Sign a message
    let message = b"Hello, XMSS!";
    let signature = keypair.sign(message);
    
    // Verify the signature
    let is_valid = keypair.public_key().verify(message, &signature, keypair.params());
    println!("Signature valid: {}", is_valid);
}
```

### Available Types

The crate re-exports the following main types for convenient access:

- `XMSSParams` - Parameters for XMSS scheme
- `XMSSKeypair` - XMSS key pair for signing and verification
- `XMSSPrivateKey` - Private key component
- `XMSSPublicKey` - Public key component
- `XMSSSignature` - Signature type
- `AuthPath` - Authentication path for Merkle tree
- `MerkleTree` - Merkle tree implementation
- `WOTSPlusParams` - WOTS+ parameters

### Important Notes

1. The keypair must be mutable when signing because XMSS is a stateful signature scheme
2. Each private key can only sign a limited number of messages (2^tree_height)
3. The verify method requires the params to be passed along with the message and signature

## Usage Example (Alternative Scheme)

To use the Hypercube signatures with TSL scheme, you can follow this example that demonstrates how to create a TSL (Tree-based Signature Layer) configuration, generate a keypair, sign a message, and verify the signature.
For now, TSL is the only supported scheme, but TL1C and TLFC using actual bigger parameters will be added in the future.

```rust
use hypercube_signatures::schemes::tsl::{TSL, TSLConfig};
use hypercube_signatures::wots::{WotsParams, WotsKeypair};

// Create TSL configuration for 128-bit security
let config = TSLConfig::new(128);
let tsl = TSL::new(config);

// Generate WOTS keypair
let params = WotsParams::from_tsl(&tsl);
let keypair = WotsKeypair::generate(&params);

// Sign a message
let message = b"Hello, world!";
let signature = keypair.sign(message, &tsl);

// Verify the signature
assert!(keypair.verify(message, &signature, &tsl));
```

## Example Projects

See the `examples/` directory in the repository for more usage examples.

## Testing

The implementation includes comprehensive test suites:

```bash
# Run unit tests
cargo test

# Run specific scheme tests
cargo test test_tsl
cargo test test_tl1c
cargo test test_tlfc

# Run with output
cargo test -- --nocapture
```
