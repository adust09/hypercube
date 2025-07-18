# Hypercube Signatures

A Rust implementation of hash-based signature optimization techniques from the CRYPTO 2025 paper "At the Top of the Hypercube" by Khovratovich et al.

## Overview

This repository implements three hash-based signature schemes that achieve 20-40% reduction in verification costs compared to conventional Winternitz one-time signatures:

- **TSL (Top Single Layer)** - Maps to a single hypercube layer, no checksum required
- **TL1C (Top Layers with 1-Chain Checksum)** - Maps to multiple layers with a single checksum chain
- **TLFC (Top Layers with Full Checksum)** - Maps to multiple layers with multiple checksum chains

## Project Structure

```
src/
├── core/               # Core hypercube operations
│   ├── hypercube.rs   # Hypercube and vertex structures
│   ├── layer.rs       # Layer calculations
│   ├── mapping.rs     # Vertex-integer bijective mappings
│   └── encoding.rs    # Encoding traits
├── schemes/           # Signature scheme implementations
│   ├── tsl.rs        # TSL scheme
│   ├── tl1c.rs       # TL1C scheme
│   └── tlfc.rs       # TLFC scheme
├── crypto/           # Cryptographic primitives
│   ├── hash.rs       # SHA-256/SHA3-256 implementations
│   └── random.rs     # Secure random number generation
└── wots.rs           # Winternitz OTS implementation
```

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

## Implemented Features

### Core Components

- **Hypercube Operations**: Efficient vertex operations in $[w]^v$ hypercube space
- **Layer Calculations**: Compute layer sizes using binomial coefficients
- **Bijective Mappings**: Convert between vertices and integers within layers
- **Hash Functions**: SHA-256 and SHA3-256 with configurable hash chains

### Signature Schemes

Each scheme provides:
- Automatic parameter selection for security levels (128-bit, 160-bit)
- Message encoding with randomness
- Integration with Winternitz OTS
- Comprehensive test coverage

### TSL (Top Single Layer)
- Maps messages to a single hypercube layer
- No checksum required due to incomparability within layers
- Simplest implementation with lowest overhead

### TL1C (Top Layers with 1-Chain Checksum)
- Maps messages to multiple top layers (0 to d₀)
- Single checksum chain: `checksum = layer + 1`
- Balance between security and efficiency

### TLFC (Top Layers with Full Checksum)
- Maps messages to multiple top layers
- Multiple checksum chains using formula: $C_i = \sum_j 2^{j \bmod c} \cdot (w - a_j)$
- Highest optimization for verification cost

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

## Performance

Verification cost improvements at 128-bit security:

| Scheme | Signature Size | Verification Cost | Improvement vs WOTS |
|--------|---------------|-------------------|-------------------|
| TSL    | 64 chains     | 70 hash ops      | ~45% reduction    |
| TL1C   | 85 chains     | 54 hash ops      | ~57% reduction    |
| TLFC   | 134 chains    | 40 hash ops      | ~69% reduction    |

## Dependencies

- `sha2`: SHA-256 implementation
- `sha3`: SHA3-256 implementation
- `rand`: Cryptographically secure RNG
- `num-integer`: Binomial coefficient calculations

## References

- Paper: [At the Top of the Hypercube](https://eprint.iacr.org/2025/889.pdf)
- Authors: Dmitry Khovratovich, Mikhail Kudinov, Benedikt Wagner
- Conference: CRYPTO 2025