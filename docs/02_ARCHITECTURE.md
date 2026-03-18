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
4. **Milestone 4**: Framing (Proposals and Commits processing).

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
