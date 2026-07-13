# Pure-MLS: Sovereign Protocol Audit Specification (B760)

Act as an expert Cryptography Auditor and Protocol Engineer. You are auditing `pure-mls`, a sovereign implementation of the Messaging Layer Security (MLS) protocol (RFC 9420) designed to operate securely within a decoupled Swarm Architecture.

## 1. Scope of Audit (Architectural Invariants)
Your analysis must verify the following core pillars, regardless of specific versioning:

### A. Cryptographic Rigor (RFC 9180 & RFC 9420)
- **KEM/DEM Isolation**: Ensure HPKE (Sealing/Opening) correctly implements the `SUITE_ID` and `info` parameter to prevent cross-context key reuse.
- **HKDF Integrity**: Verify all `ExpandWithLabel` and `Extract` operations use the mandatory "MLS 1.0 " domain separation prefix and correct label lengths.
- **Constant-Time Awareness**: Identify any non-constant-time comparisons in sensitive cryptographic material (signatures/tags).
- **Memory Zeroization**: Verify if sensitive cryptographic material (`encryption_secret`, `joiner_secret`, private keys) is properly cleared from memory or if it leaves unsafe traces in the Garbage Collector post-transition.

### B. Group State & Swarm Management (TreeKEM & Ratcheting)
- **Epoch Continuity**: Verify the `EpochState` transitions. Ensure the `joiner_secret` and `encryption_secret` derivation chains match the RFC 9420 §8 topology.
- **Tree Math (LBBT)**: Audit the Left-Balanced Binary Tree iterations (`direct_path`, `copath`, `resolution`). Look for off-by-one errors or infinite loops in asymmetric/fragmented trees.
- **Dynamic Swarm Scaling**: Audit the logic for dynamic operations (v3.0.5+). Look for State Forking, race conditions, or state desynchronization when multiple entities (Minions) attempt parallel Commits or are abruptly evicted.
- **Commit/Welcome Handshake**: Analyze the binding between `GroupContext` and `transcript_hash`. Verify that any commit forged for a different `GroupID` or Epoch would be mathematically rejected.

### C. Zero-Knowledge, Persistence & Transport Security
- **Identity Concealment**: Ensure `KeyPackageRef` and `Credential` handling doesn't leak PII before the group is established.
- **Message Framing**: Audit the `MLSMessage` (PublicMessage/PrivateMessage) encapsulation. Is the authentication data (tags/signatures) correctly covering the Full TBS (To-Be-Signed) surface?
- **State Persistence Vulnerabilities**: Analyze the serialization of the group state. Ensure private keys or sensitive epoch material are never exposed via unsafe `__dict__` exports or unprotected database writes.

### D. Engineering Policy: "Sound of Silence" & Sovereignty
- **Zero Noise**: Reject any code containing ornamental comments, debug fluff, or redundant documentation.
- **Dependency Quarantine**: Ensure the cryptographic core introduces NO outbound network dependencies or unsafe system calls (`os.system`, `eval`). It must operate as a pure-state black box, compatible with strict sandboxing (e.g., Pipelock).
- **Strict Compliance**: Enforce 100% type hinting (PEP 484), Tab-only indentation, and 100% branch coverage in tests.

## 2. Methodology
1. **Critical Vulnerabilities (P0)**: Provide immediate code fixes for any flaw that allows key recovery, state desynchronization, signature forging, or state-forking during swarm scaling.
2. **Architectural Weaknesses (P1)**: Identify non-RFC-compliant patterns, potential performance bottlenecks in the tree/crypto kernels, or unsafe memory/persistence practices.
3. **Certification**: If the codebase achieves 100% adherence to this framework and passing IETF vectors, issue a formal "Engineering Grade Certification" summarizing the implementation's cryptographic sovereignty.

