# pure-mls: Sovereign Roadmap

Strategic direction and protocol-hardening milestones.

## Current status (v4.0.0 — Fable audit remediation)

`pure-mls` is an **experimental, not-yet-production-audited** implementation of
RFC 9420 (ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` / `0x0001` only).
After the 4.0.0 audit remediation it is verified **offline** against the IETF
known-answer vectors: `crypto-basics` (incl. `DeriveKeyPair`), `key-schedule`,
`secret-tree`, `passive-client-welcome`, and `tree-validation` (tree_hash + resolution
match OpenMLS across all tree sizes, including non-power-of-two / post-removal trees).
Protocol logic is pure Python; cryptographic primitives are delegated to the
`cryptography` library.

## 1. Interoperability

- **Live bidirectional OpenMLS interop — PARKED (2026-07).** Round-trips in both
  directions (OpenMLS ↔ pure-mls) plus active operations (Commit/Add/Remove) validated
  against a live `openmls-cli`. **Deprioritized on purpose:** OpenMLS was used mainly as
  a *test oracle* to validate our own implementation, and full cross-implementation
  wire-compatibility is not a current requirement. The tree / primitives /
  passive-client-welcome layer is already vector-verified offline. Resume here (Phase 1:
  OpenMLS→pure-mls join; Phase 2: pure-mls→OpenMLS + active ops) if cross-implementation
  deployments ever become a goal.
- **Additional ciphersuites**: only `0x0001` is implemented today.
- ~~Auto-detect dialect from the wire~~: **removed in 4.0.0** — selecting a codec from
  attacker-controllable leading bytes is a security hazard. Non-standard dialects are
  opt-in via an explicit `dialect=` argument only.

## 2. Infrastructure & Compliance

- **FIPS 140-3 alignment**: keep the cryptographic surface FIPS-friendly (Ed25519,
  X25519, AES-128-GCM, HKDF-SHA256).
- **Dependency stance**: protocol logic stays pure Python; cryptographic primitives
  remain delegated to a vetted library (`cryptography`) rather than reimplemented —
  "sovereign" here means *auditable protocol code*, not hand-rolled crypto.

## 3. Advanced Protocol Features

- **External PSK lifecycle**: harden the PSK binder logic for large-scale deployments.
- **TreeKEM state persistence**: optimized serialization for large trees.
- **Production hardening**: an external security review is required before any
  production use.
