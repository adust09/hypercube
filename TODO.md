# TODO

## XMSS Implementation

### High Priority
- [ ] Debug signature verification issue
  - Root mismatch between expected and computed values
  - Likely issue with WOTS key reconstruction or tree traversal
  - Check message digest computation consistency between sign/verify

### Medium Priority  
- [ ] Add comprehensive benchmarks
  - Compare standard XMSS vs hypercube-optimized XMSS
  - Measure verification time improvements (expected 20-40% reduction)
  - Test with different tree heights (h=10, 16, 20)
  
### Low Priority
- [ ] Fix existing WOTS tests broken by interface changes
  - Update test_wots.rs to use new sign() method signature
  - Add encoding parameter to sign calls
  
- [ ] Add more XMSS test cases
  - Test with SHA3-256 hash function
  - Test key exhaustion handling
  - Test deterministic key generation

### Code Quality
- [ ] Remove unused `wots_keys` field warning in XMSSPrivateKey
- [ ] Add proper error handling instead of panics
- [ ] Document public API with rustdoc comments