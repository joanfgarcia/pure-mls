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
We strictly enforce the **"Sound of Silence"** code standard via `ruff` en el fichero `pyproject.toml`:
- Pure Tabulations (`\t`) for minimal character footprint (`W191` allowance).
- Zero dead code allowed.
- Semantic silence: no unused variables, no noisy legacy warnings, no auto-generated visual clutter (`tests/protos/*` excluidos).

## 🗺️ Architecture (Project Map)
```text
pure-mls/
├── README.md               # Este archivo
├── CHANGELOG.md            # Registro histórico de versiones
├── pyproject.toml          # Dependencias (uv) y conf Sound of Silence (Ruff)
├── src/
│   └── pure_mls/
│       ├── group.py        # [API] Máquina del estado (MLSGroup)
│       ├── tree.py         # Nodos y estructura del RatchetTree
│       ├── tree_math.py    # Matemáticas de índices LBBT
│       ├── epoch.py        # Estados inmutables (Epochs)
│       ├── keys.py         # Identidades Ed25519 y KEMs X25519
│       ├── keyschedule.py  # Derivación de Secretos (Application_Key)
│       └── hpke.py         # Hybrid Public Key Encryption Base Mode
└── tests/
    ├── test_group.py       # Pruebas unitarias de State Machine
    ├── test_e2e_websockets.py # E2E Websockets local
    ├── test_e2e_mqtt.py    # E2E broker.hivemq.com (IoT)
    ├── test_e2e_webrtc.py  # E2E Data Channels P2P (aiortc)
    └── test_e2e_grpc.py    # E2E Backend Swarm (Proto Hub)
```

## 🔌 API Quickstart
La máquina de estado central es `MLSGroup`. Instálalo en tu cerebro:

```python
from pure_mls.group import MLSGroup
from pure_mls.keys import SignatureKey, KemKey

# 1. El Creador (Alice) inicia el Sovereign Group
alice_group = MLSGroup.create(b"grupo-soberano", SignatureKey(), KemKey())

# 2. Alice recibe el `KeyPackage` de Bob por la red y lo añade al Árbol
alice_next, welcome, update = alice_group.add_member(bob_kp)

# 3. Bob captura el `Welcome` (sellado con HPKE) de la red y lo descifra uniéndose
bob_group = MLSGroup.join(welcome, 2, SignatureKey(), KemKey())

# La Verdad Matemática Subyacente:
assert alice_next.application_key == bob_group.application_key
```

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3).
