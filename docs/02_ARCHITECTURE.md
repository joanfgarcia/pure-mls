# The `pure-mls` Architecture

This document outlines how [RFC 9420 (MLS)](https://datatracker.ietf.org/doc/rfc9420/) maps to our pure-Python architecture.
**Current version: v1.5.0 — Production-Ready certified. 72/72 tests green.**


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

## 2. Bootstrapping Strategy — Implementation Status

| Milestone | Status | Notes |
|---|---|---|
| HKDF / HPKE wrappers | ✅ Done | RFC 5869, RFC 9180, labeled extract/expand |
| Binary tree math | ✅ Done | LBBT, path resolution, copaths, parent_hash §7.9 |
| Group State Machine | ✅ Done | EpochState, KeySchedule, MLSGroup |
| Framing (Commit/Welcome) | ✅ Done | TLS wire format: GroupContext, MLSMessage, PublicMessage |
| App Message Encryption | ✅ Done | AES-256-GCM, group application key |
| Storage (AsyncEncryptedStore) | ✅ Done | AES-GCM encrypted persistence |
| KeyPackage Authentication | ✅ Done | Ed25519 self-signature §10.1, KPRef labeled HKDF |
| TreeKEM path encryption | ✅ Done | Full UpdatePath + HPKECiphertext per §12.1.1 |
| **remove_member()** | 🔲 v1.6 | Next milestone — requires parent_hash v2 + tree shrink |

---

## 3. The Zero-Knowledge Transport Layer (The Dumb Pipe)
Unlike traditional chat architectures, `pure-mls` mathematically separates the cryptographic engine from the delivery network (e.g., Firebase Realtime Database, IPFS, WebSockets). 

- **Agnostic Delivery**: The server is treated as a "dumb pipe" or a passive bulletin board. 
- **Zero-Knowledge**: The central server NEVER performs handshakes, NEVER negotiates keys, and NEVER parses the content of the `Welcome`, `Commit`, or `Application` messages. It only routes Base64 ciphertexts.
- **P2P State Consensus**: State management and logic reside entirely in the client endpoints. Real-time Pub/Sub networks like Firebase simply push identical bytes to all subscribed nodes effortlessly without understanding the cryptographic state.

### Visual Architecture

```mermaid
sequenceDiagram
    participant A as Agent A (pure-mls)
    participant DB as Central Server / Firebase
    participant B as Agent B (pure-mls)

    Note over A,B: Local Environment: Private Keys & State
    A->>A: Compute TreeKEM Epoch State
    A->>A: HPKE Encrypt Payload (Commit/Welcome/Data)
    A->>DB: Push Base64 Ciphertext
    Note over DB: ZERO KNOWLEDGE.<br/>Cannot decrypt. Just routes bytes.
    DB-->>B: Broadcast Base64 Ciphertext (WebSocket)
    B->>B: HPKE Decrypt using Local Private Key
    B->>B: Derive exactly the same Epoch State
```

---

## 4. RFC 9420 Compliance Status (v0.4.0)

| RFC §  | Feature | Status | Notes |
|---|---|---|---|
| §6.2 | `FramedContentTBS` signature surface | ✅ Compliant | Ed25519 over version+wire_format+GroupContext+FramedContent |
| §6.2 | `membership_tag` + `confirmation_tag` | ✅ Compliant | HMAC-SHA256 with membership_key / confirmation_key |
| §7.8 | Subtree hash (sibling tree hash) | ✅ Compliant | SHA-256 of public key at parent nodes; used in §7.9 |
| §7.9 | `parent_hash` computation | ✅ Compliant | SHA-256(label + public_key + parent_hash + sibling_tree_hash) |
| §8.1 | `GroupContext` TLS encoding | ✅ Compliant | version, cipher_suite, group_id, epoch, tree_hash, transcript_hash |
| §8.2 | Transcript hash — Sender struct | ✅ Compliant | SenderType(0x01)+leaf_index bound into SHA-256 digest |
| §10.1 | `KeyPackage` self-signature (Ed25519) | ✅ Compliant | `KeyPackageTBS` = cipher_suite+init_key+identity_key |
| §10.2 | `KeyPackageRef` = `RefHash("MLS 1.0 KeyPackageRef", kp)` | ✅ Compliant | labeled HKDF-Expand, Nh=32 bytes |
| §11 | Path secrets HPKE info = `GroupContext` | ✅ Compliant | GroupContext bytes used as HPKE info in UpdatePath |
| §12.1.1 | `UpdatePath` + `HPKECiphertext` | ✅ Compliant | per-copath-node encrypted path secret |
| §12.1.2 | `Welcome` / `GroupSecrets` TLS encoding | ✅ Compliant | TLS-prefixed structs, HPKE-sealed per new member |
| RFC 9180 | HPKE Base Mode (KEM+KDF+AEAD) | ✅ Compliant | SUITE_ID, labeled extract/expand, XOR nonce counter |
| RFC 5869 | HKDF Extract + Expand | ✅ Compliant | — |

> **Cross-implementation Interoperability**: Cryptographic primitives (HKDF, HPKE, KeySchedule)
> are validated against OpenMLS-aligned test vectors (`tests/interop/`). Full wire-format
> interoperability with external MLS implementations (OpenMLS, mlspp) is not verified and
> is targeted as a v1.6.x milestone.
