# Phase 4: Public API & Persistence (Design Blueprint)

This document formalizes the architectural decisions made for the external `pure-mls` interface. The goal is to provide a purely functional, asynchronous API while securely offloading state persistence to the library (alleviating the caller from managing raw binary blobs).

## 1. The Persistence Abstraction (`AsyncEncryptedStore`)
To prevent the caller (e.g., Red Pill) from managing complex SQLite locks or raw blobs, `pure-mls` will ship with a built-in Encrypted File Store.
- **Format**: Flat file hierarchy (`mls_data/groups/legion_770.state`).
- **Encryption**: AES-256-GCM encrypted *at rest*.
- **Key Management**: The `master_key` is NEVER stored on disk by `pure-mls`. It is expected to be passed dynamically at runtime (e.g., from Red Pill's memory-loaded `SWARM_SHARED_SECRET`).

```python
class AsyncEncryptedStore:
    def __init__(self, storage_dir: str, master_key: str):
        # master_key is strictly held in RAM
        self.dir = storage_dir
        self.key = master_key

    async def save_state(self, group_id: str, state_bytes: bytes) -> None: ...
    async def load_state(self, group_id: str) -> bytes: ...
```

## 2. The Functional Asynchronous API
`pure-mls` will not run any background daemons. It is strictly invoked on-demand. All network I/O (Firebase, WebSockets, MQTT) is external to this library.

```python
# Example Usage by Red Pill Orchestrator

import pure_mls

# 1. Initialize the disk connector (Stateless configuration)
store = pure_mls.AsyncEncryptedStore(
    storage_dir="./mls_data", 
    master_key=os.getenv("SWARM_SHARED_SECRET")
)

# 2. Encrypt an outgoing message (Modifies epoch state in disk)
ciphertext = await pure_mls.encrypt_message(
    group_id="legion_770", 
    store=store, 
    plaintext=b"Hello Swarm"
)

# 3. Process an incoming payload from Firebase (Advances epoch via Commit/Welcome)
plaintext = await pure_mls.process_incoming(
    group_id="legion_770",
    store=store,
    payload=incoming_bytes
)
```

## 3. Strict Guidelines
- **Zero-Daemon**: The library wakes up, decrypts state, computes cryptography, encrypts new state, and dies.
- **Zero-Trust**: Without the `master_key` passed from the caller's `.env`, the `/mls_data/` directory is mathematically impenetrable (Plausible Deniability).
