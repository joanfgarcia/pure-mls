# pure-mls

`pure-mls` is a zero-dependency, pure Python implementation inspired by the Messaging Layer Security (MLS) protocol ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)). This project provides the core state machine for High-Level secure group messaging, using HPKE-inspired constructions for the Key Schedule.

## 🚀 Features & Transports
`pure-mls` has been rigorously verified E2E over the following transports, passing 100% of its hermetic tests:
- **WebSockets:** Standard duplex streams.
- **MQTT (IoT):** Stateless pub/sub routing via `aiomqtt`.
- **WebRTC (P2P):** Zero-trust direct Data Channels (`aiortc`) using SDP negotiation.
- **gRPC (Swarm Backend):** Centralized directory routing for huge distributed edge clusters (`grpcio`).

## 🧠 Philosophy: "Sound of Silence"
The goal is **Absolute Purity**:
- No compiled bindings (no Rust, C++ or FFI).
- Operates natively in any Python 3.12+ environment.
- Suitable for zero-friction edge computing and standard backend runtimes.
- Built on principles of [Plausible Deniability and Zero-Knowledge](docs/00_MANIFESTO.md).

### The Linter Protocol
We strictly enforce the **"Sound of Silence"** code standard via `ruff` in the `pyproject.toml` file:
- Pure Tabulations (`\t`) for minimal character footprint (`W191` allowance).
- Zero dead code allowed.
- Semantic silence: no unused variables, no noisy legacy warnings, no auto-generated visual clutter (`tests/protos/*` excluded).

## 🗺️ Architecture (Project Map)
```text
pure-mls/
├── README.md               # This file
├── CHANGELOG.md            # Version history registry
├── pyproject.toml          # Dependencies (uv) and Sound of Silence config (Ruff)
├── src/
│   └── pure_mls/
│       ├── group.py        # [API] State Machine (MLSGroup)
│       ├── tree.py         # Nodes and RatchetTree structure
│       ├── epoch.py        # Immutable states (Epochs)
│       ├── keys.py         # Ed25519 Identities and X25519 KEMs
│       ├── keyschedule.py  # Secret Derivation (Application_Key)
│       └── hpke.py         # Hybrid Public Key Encryption Base Mode
└── tests/
    ├── test_group.py       # State Machine unit tests
    ├── test_e2e_websockets.py # E2E local Websockets
    ├── test_e2e_mqtt.py    # E2E broker.hivemq.com (IoT)
    ├── test_e2e_webrtc.py  # E2E Data Channels P2P (aiortc)
    └── test_e2e_grpc.py    # E2E Backend Swarm (Proto Hub)
```

## 🔌 API Quickstart
The central state machine is `MLSGroup`. Install it in your brain:

```python
from pure_mls.group import MLSGroup
from pure_mls.keys import SignatureKey, KemKey

# 1. Each participant generates their own persistent identity keys
alice_sig, alice_kem = SignatureKey(), KemKey()
bob_sig, bob_kem = SignatureKey(), KemKey()

# 2. The Creator (Alice) initializes the Sovereign Group
alice_group = MLSGroup.create(b"grupo-soberano", alice_sig, alice_kem)

# 3. Alice receives Bob's `KeyPackage` (his public keys + identity) over the network
bob_kp = MLSGroup.create_key_package(bob_sig, bob_kem)
alice_next, welcome, update = alice_group.add_member(bob_kp)

# 4. Bob decrypts the Welcome (sealed with HPKE to his KEM key) and joins
bob_group = MLSGroup.join(welcome, bob_sig, bob_kem)

# The Underlying Mathematical Truth:
assert alice_next.application_key == bob_group.application_key
```

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3).
