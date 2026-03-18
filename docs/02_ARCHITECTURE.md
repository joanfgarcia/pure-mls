# The `pure-mls` Architecture Plan

This document outlines how the [RFC 9420 Messaging Layer Security](https://datatracker.ietf.org/doc/rfc9420/) standard maps to our pure Python architecture.

## 1. The Separation of Concerns
Following strict software engineering guidelines, the library is decoupled into 4 distinct layers:

### Layer 1: Core Cryptography (`pure_mls.crypto`)
- This layer wraps standard Python libraries (like the standard `hashlib`, `hmac`, and `cryptography.io` curves) into MLS-compliant Ciphersuites.
- Handles HKDF (HMAC-based Key Derivation Function) Extract and Expand.
- Handles HPKE (Hybrid Public Key Encryption - RFC 9180) which is mandatory for MLS `Welcome` messages and tree updates.

### Layer 2: The TreeKEM Mathematics (`pure_mls.tree`)
- Implements the Left-Balanced Binary Tree required by MLS.
- `Node` classes: `LeafNode`, `ParentNode`.
- Path resolution logic: Computing direct paths, copaths, and node resolutions when a leaf updates its keys.

### Layer 3: Group State Machine (`pure_mls.epoch`)
- `EpochState`: The immutable object holding the current State (Tree, Group ID, Epoch ID, Current Key Schedule).
- Manages the derivation of the `SenderDataSecret`, `EncryptionSecret`, and `ConfirmationKey` from the `EpochAuthenticator`.

### Layer 4: High Level API / Framing (`pure_mls.group`)
- The developer-facing API: `MlsGroup`.
- `add_member()`, `remove_member()`, `update()`.
- Generates `MLSCiphertext` (fully framed and encrypted end-to-end messages ready for network distribution).

---

## 2. Bootstrapping Strategy
We will build this package incrementally by proving the layers with Pytest against the official MLS Test Vectors.
1. **Milestone 1**: HKDF and HPKE wrappers (Cryptography primitive foundation).
2. **Milestone 2**: Array-Based Binary Tree algorithms.
3. **Milestone 3**: KeySchedule and Epoch rotation.
4. **Milestone 4**: Framing (Proposals and Commits processing).
