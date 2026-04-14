# Changelog

## 0.2.0

- **Signing compatibility confirmed**: `pqcrypto-dilithium` v0.5 (shell-chain) implements FIPS 204 ML-DSA-65, byte-identical with `@noble/post-quantum` `ml_dsa65`. The `Dilithium3` alias in the SDK now documents this equivalence explicitly (pk=1952, sk=4032, sig=3309 bytes).
- add cross-validation tests verifying ML-DSA-65 key/signature sizes against chain expectations
- add `MlDsa65Adapter` round-trip sign+verify test
- clarify `adapters.ts` JSDoc: both `"Dilithium3"` and `"MlDsa65"` route to ML-DSA-65 (FIPS 204) which is wire-compatible with the chain's Dilithium3 verifier

## 0.2.0-rc.1

- add Browser and Node integration tests for signer, keystore, and provider flows
- add Rust compatibility vectors for address derivation and transaction hashing
- fix `hashTransaction()` to match the Rust node's canonical RLP field ordering
- fix `hashTransaction()` to accept canonical `pq1...` recipient addresses
- narrow the package root export surface to stable application-facing APIs
- document extension background flow, minimal dApp usage, and release checklist
