# pure-mls

`pure-mls` is a pure-Python implementation of the Messaging Layer Security (MLS) protocol ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)) — the protocol logic (TreeKEM, key schedule, wire format) is written in Python, while cryptographic primitives are delegated to the [`cryptography`](https://pypi.org/project/cryptography/) library. It implements the cryptographic state machine for secure group messaging.

> ⚠️ **Status: experimental, not audited for production.** It passes the offline IETF known-answer vectors below, but several protocol-level guarantees (e.g. `tree_hash` interop, full parent-hash validation) are still being hardened. Do not use it to protect real secrets yet.

## 🚀 Features & Interoperability
What is actually verified today (offline, in CI):
- **RFC 9420 primitives**: HPKE / HKDF / key-schedule and `DeriveKeyPair` match the IETF `crypto-basics` and `key-schedule` known-answer vectors.
- **Passive-client Welcome + PSK**: passes the IETF `passive-client-welcome` and `psk_secret` vectors (Welcome produced by a reference implementation, joined by `pure-mls`).
- **Transports**: local end-to-end demos over WebSockets, MQTT, WebRTC and gRPC (network-marked, skipped by default).

Not yet backed: live *bidirectional* OpenMLS interop (round-trips in both directions) is not wired up.

## 🧠 Philosophy: "Sound of Silence"
The goal is **protocol purity**:
- All MLS protocol logic (TreeKEM, key schedule, TLS wire format) is pure Python — no protocol logic hidden in native code.
- The single dependency, `cryptography`, provides the vetted low-level primitives (Ed25519, X25519, AES-GCM, HKDF) rather than reimplementing them.
- Operates natively in any Python 3.12+ environment.
- Built on principles of [Plausible Deniability and Zero-Knowledge](https://github.com/joanfgarcia/pure-mls/blob/main/docs/00_MANIFESTO.md).

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
│       ├── crypto.py       # Parent/subtree hashes and HPKE info helpers
│       ├── tls.py          # RFC 9420 / TLS 1.3 Wire Format Primitives
│       ├── extensions.py   # MLS Extensions Framework
│       ├── proposals.py    # Group Operations (Add, Update, Remove)
│       ├── epoch.py        # Immutable states (Epochs)
│       ├── keys.py         # Ed25519 Identities and X25519 KEMs (+ DeriveKeyPair)
│       ├── hkdf.py         # HKDF / ExpandWithLabel primitives
│       ├── keyschedule.py  # Secret Derivation (Key Schedule §8)
│       ├── secret_tree.py  # Per-leaf per-generation SecretTree (§9)
│       ├── hpke.py         # Hybrid Public Key Encryption Base Mode
│       ├── codecs.py       # Dialect / codec plugin system (wire-format variants)
│       ├── storage.py      # AES-256-GCM encrypted state persistence
│       └── cli.py          # Command-line interface
└── tests/
    ├── test_ietf_vectors.py # RFC 9420 IETF known-answer vectors (offline)
    ├── test_group.py       # State Machine unit tests
    ├── test_e2e_websockets.py # E2E local Websockets (network-marked)
    ├── test_e2e_mqtt.py    # E2E local broker (IoT, network-marked)
    ├── test_e2e_webrtc.py  # E2E Data Channels P2P (aiortc, network-marked)
    └── test_e2e_grpc.py    # E2E Backend Swarm (gRPC, network-marked)
```
## 📚 Documentation & Guides
We believe in making cryptography accessible. For a fast, pragmatic, and irreverent introduction to MLS, check our Primate Survival Guide:
- 🦍 [The Primate Survival Guide to pure-mls (EN)](https://github.com/joanfgarcia/pure-mls/blob/main/docs/03_MLS_FOR_PRIMATES_EN.md)
- 🦍 [Guía del Primate Sobreviviendo a pure-mls (ES)](https://github.com/joanfgarcia/pure-mls/blob/main/docs/03_MLS_FOR_PRIMATES_ES.md)

For a deeper dive into the architecture, mathematics, and philosophy of the protocol, explore the Human Journey:
- 🇺🇸 [The Human Guide to MLS: The Journey (EN)](https://github.com/joanfgarcia/pure-mls/blob/main/docs/02_MLS_JOURNEY_EN.md)
- 🇪🇸 [La Guía Humana de MLS: El Viaje (ES)](https://github.com/joanfgarcia/pure-mls/blob/main/docs/02_MLS_JOURNEY_ES.md)

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

# 5. Alice removes Bob from the group
alice_next_epoch, remove_commit = alice_next.remove_member(bob_group.committer_index)

# The Underlying Mathematical Truth:
assert alice_next.application_key == bob_group.application_key
assert alice_next_epoch.application_key != bob_group.application_key  # Bob is out!
```

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3).
