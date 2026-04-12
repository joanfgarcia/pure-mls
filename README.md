# pure-mls

`pure-mls` is a zero-dependency, pure Python implementation of the Messaging Layer Security (MLS) protocol ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)). This project provides a production-grade cryptographic state machine for secure group messaging.

## 🚀 Features & Interoperability
`pure-mls` has achieved full cryptographic interoperability with the IETF standard, passing 100% of the **Passive Client Welcome** and **PSK Resolution** test vectors (OpenMLS benchmark):
- **RFC 9420 Compliant**: Full implementation of the TreeKEM and Key Schedule lifecycle.
- **IETF Vector Verification**: 100% pass rate on interoperability suites.
- **Transports**: Verified E2E over WebSockets, MQTT (IoT), WebRTC (P2P), and gRPC.

## 🧠 Philosophy: "Sound of Silence"
The goal is **Absolute Purity**:
- No compiled bindings (no Rust, C++ or FFI).
- Operates natively in any Python 3.12+ environment.
- Suitable for zero-friction edge computing and standard backend runtimes.
- Built on principles of [Plausible Deniability and Zero-Knowledge](docs/00_MANIFESTO.md).

### The Linter Protocol
We strictly enforce the **"Sound of Silence"** code standard via `ruff` in the `pyproject.toml` file:
- **Zero-Warning State**: 100% clean status under Ruff's most rigorous rules.
- Pure Tabulations (`\t`) for minimal character footprint (`W191` allowance).
- Zero dead code allowed.

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
│       ├── tls.py          # RFC 9420 / TLS 1.3 Wire Format Primitives
│       ├── extensions.py   # MLS Extensions Framework
│       ├── proposals.py    # Group Operations (Add, Update, Remove)
│       ├── epoch.py        # Immutable states (Epochs)
│       ├── keys.py         # Ed25519 Identities and X25519 KEMs
│       ├── keyschedule.py  # Secret Derivation (Application_Key)
│       └── hpke.py         # Hybrid Public Key Encryption Base Mode
└── tests/
    ├── test_ietf_vectors.py # 100% RFC 9420 Interop (IETF/OpenMLS)
    ├── test_group.py       # State Machine unit tests
    ├── test_e2e_websockets.py # E2E local Websockets
    ├── test_e2e_mqtt.py    # E2E broker.hivemq.com (IoT)
    ├── test_e2e_webrtc.py  # E2E Data Channels P2P (aiortc)
    └── test_e2e_grpc.py    # E2E Backend Swarm (Proto Hub)
```
## 📚 Documentation & Guides
We believe in making cryptography accessible. If mathematical algorithms and RFCs feel daunting, you can read our Colloquial Guides, available in multiple languages:
- 🇺🇸 [The Human Guide to MLS: The Journey (EN)](docs/02_MLS_JOURNEY_EN.md)
- 🇪🇸 [La Guía Humana de MLS: El Viaje (ES)](docs/02_MLS_JOURNEY_ES.md)

*Contributors: We welcome translations! Feel free to PR your language following the `02_MLS_JOURNEY_XX.md` format.*

## 🔌 API Quickstart
The central state machine is `MLSGroup`. Install it in your brain:

```python
from pure_mls.group import MLSGroup
from pure_mls.keys import SignatureKey, KemKey

# 1. Each participant generates their own persistent identity keys
alice_sig, alice_kem = SignatureKey(), KemKey()
bob_sig, bob_kem = SignatureKey(), KemKey()

# 2. Alice initializes the Sovereign Group
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
