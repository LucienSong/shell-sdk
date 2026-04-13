# Changelog

## 0.2.0-rc.1

- add Browser and Node integration tests for signer, keystore, and provider flows
- add Rust compatibility vectors for address derivation and transaction hashing
- fix `hashTransaction()` to match the Rust node's canonical RLP field ordering
- fix `hashTransaction()` to accept canonical `pq1...` recipient addresses
- narrow the package root export surface to stable application-facing APIs
- document extension background flow, minimal dApp usage, and release checklist
