# Hypercube

A Rust implementation of [At the Top of the Hypercube](https://eprint.iacr.org/2025/889.pdf) by Khovratovich et al.

## Building

```bash
# Build in release mode
cargo build --release

# Run all tests
cargo test

# Run benchmarks
cargo bench
```

## Usage Example

To use the Hypercube signatures, you can follow this example that demonstrates how to create a TSL (Tree-based Signature Layer) configuration, generate a keypair, sign a message, and verify the signature.
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
