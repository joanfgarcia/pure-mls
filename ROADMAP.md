# pure-mls: Sovereign Roadmap

Future strategic directions and protocol hardening milestones.

## 1. Interoperability & Adaptability
- **Adaptive Implementation Dialects**: Implement a "codec plugin" system to handle subtle wire-format variations between major implementations (OpenMLS, mlspp, Cisco).
  - Define `SerializerStrategy` protocols.
  - Implement "Auto-Detect Dialect" logic in the `Welcome` handshake.
- **Full IETF Vector coverage**: Achieving 100% pass rate across all published test vectors.

## 2. Infrastructure & Compliance
- **FIPS 140-3 Alignment**: Narrowing the cryptographic surface to FIPS-friendly primitives (Ed25519, X25519).
- **Zero-Dependency Core**: Eliminating non-sovereign runtime dependencies to ensure long-term stability in Bünker environments.

## 3. Advanced Protocol Features
- **External PSK Lifecycle**: Hardening the PSK binder logic for large-scale deployments.
- **TreeKEM State persistence**: Optimized serialization for large trees (>1M members).
