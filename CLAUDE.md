# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This is a **research specification repository** containing technical documentation for hash-based signature optimization techniques from the CRYPTO 2025 paper "At the Top of the Hypercube – Better Size-Time Tradeoffs for Hash-Based Signatures" by Dmitry Khovratovich, Mikhail Kudinov, and Benedikt Wagner. 

**Important**: This repository contains only documentation - no implementation code exists yet.

## Key Reference Document

The primary content is in `README.md` which contains comprehensive technical specifications in Japanese, including:

### Critical Sections for Implementers
- **Section 2**: Core algorithm specifications for TLFC, TL1C, and TSL schemes
- **Section 3**: Winternitz one-time signature scheme implementation details  
- **Section 4**: Security properties and proofs
- **Section 5**: Performance characteristics and optimization bounds
- **Section 7**: Recommended parameter values for different security levels

### Mathematical Foundations
- Hypercube structure `[w]^v` with layer organization (Section 2.1)
- Encoding functions and collision metrics (Section 1.2) 
- Vertex mapping algorithms (Section 6.1)
- Security parameter relationships and bounds (Section 4)

## Implementation Guidance

When implementing these algorithms:

### Algorithm Priority
1. **TSL (Top Single Layer)**: Simplest to implement, no checksum required
2. **TL1C (Top Layers with 1-Chain Checksum)**: Moderate complexity
3. **TLFC (Top Layers with Full Checksum)**: Most complex but highest optimization

### Key Implementation Components
- Non-uniform mapping function Ψ (critical for security)
- Layer size calculations using binomial coefficients
- Efficient vertex-to-integer and integer-to-vertex mappings
- Hash chain computations `H^k(x)`

### Parameter Selection
Reference README.md Section 7 for security-level appropriate parameters:
- 128-bit security: v=132,84,64 with corresponding w values
- 160-bit security: v=168,104,80 with corresponding w values

## Research Context

This work achieves 20-40% verification cost reduction over previous Winternitz schemes while maintaining security guarantees. The theoretical lower bounds are provided in Theorem 1 (README.md Section 5.2).

**Original Paper**: Available at https://eprint.iacr.org/2025/889.pdf

## Japanese Project Notes

- このプロジェクトはpaperの定義対して厳密な実装をするのが目的です。