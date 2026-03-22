# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-22

### Added

- **[SECURITY] STATE-02 — Full GroupInfo Transcript Hash (RFC 9420 §8.2)**: `transcript_hash` now
  covers `group_id`, `cipher_suite` (fixed `0x0001`), `epoch_id`, `tree`, `confirmation_key`,
  `ciphertexts`, `extensions`, and `sender`. Previously missing fields allowed a theoretical
  group-ID substitution attack; now any commit forged for a different group ID fails Ed25519
  signature verification. Implemented in new `_transcript_hash()` helper; both `add_member` and
  `process_update` use it consistently.
- **[SECURITY] STATE-04 — KeyPackageRef Hashing (RFC 9420 §10.2)**: `GroupUpdate.encrypted_commit_secrets`
  is now keyed by `KeyPackageRef = SHA-256(kp.to_bytes())[:16]` (bytes) instead of tree leaf index
  (int). This makes commit-secret lookup resilient to KEM key rotation: the ref is stable as long as
  the member does not generate a brand-new `KeyPackage` within the same epoch. New `_make_kp_ref()`
  helper exported from `pure_mls.group`.
- **[QA] `tests/test_state_findings.py`** (8 new tests): `test_transcript_hash_includes_group_id`,
  `test_transcript_hash_includes_sender`, `test_group_id_substitution_attack_rejected`,
  `test_legitimate_process_update_still_works`, `test_kp_ref_is_deterministic`,
  `test_kp_ref_differs_for_different_keys`, `test_commit_secrets_keyed_by_kp_ref`,
  `test_process_update_uses_kp_ref_not_index`. **43/44 tests green** (MQTT excluded: no broker).

### Fixed

- **[QUALITY] W293 Lint** — 12 blank-line-with-whitespace errors in `group.py` cleared by
  `ruff --fix`. All lint checks now pass (Sound of Silence policy maintained).
- **`tests/test_group_errors.py`** — Updated to use `KeyPackageRef` (bytes) keys and
  `_transcript_hash()` for constructing mock `GroupUpdate` objects, replacing the old
  int-indexed schema.

## [0.2.3] - 2026-03-22

### Fixed
- **[CRITICAL] NEW-02 RFC 9180 Interoperability**: Fixed salt handling in `hpke.py` by correctly passing `None` instead of `b""` to `hkdf_extract`, ensuring the standard-compliant zero-vector salt substitution.

## [0.2.2] - 2026-03-22

### Fixed
- **[CRITICAL] CRIT-03 Key Rotation Resilience**: Implemented structural fix by switching `encrypted_commit_secrets` from public-key-based to leaf-index-based lookup.
- **[MODERATE] MOD-01 HKDF Test Alignment**: Synchronized `test_hkdf.py` with the v0.2.1 `None` salt logic.
- **[QUALITY] NEW-01 MQTT Test Alignment**: Fixed assertion mismatch in `test_e2e_mqtt.py`.
- **[POLICY] QUAL-01 TODO Removal**: Removed the remaining `TODO (STATE-02)` from `group.py`.

## [0.2.1] - 2026-03-22

### Fixed
- **[CRITICAL] CRIT-01 HPKE Context Isolation**: Implemented mandatory `info` parameter in `HPKE.seal` and `HPKE.open` (RFC 9180 §4.1) to prevent cross-context key reuse.
- **[CRITICAL] CRIT-02 HKDF Parameter Alignment**: Corrected transposed `salt` and `ikm` arguments in `KeySchedule.derive` and `MLSGroup.join` to strictly align with RFC 9420 §8.1.
- **[CRITICAL] CRIT-03 Key Rotation Resilience**: Fixed an issue in `MLSGroup.process_update` that could lead to silent desynchronization during KEM key rotation. Improved error reporting for missing recipient keys.
- **[MODERATE] MOD-01 HKDF Salt Handling**: Clarified `hkdf_extract` behavior to correctly distinguish between `None` and an empty `b""` salt.
- **[QUALITY] Sound of Silence Enforcement**: Removed policy-violating comments, fixed trailing whitespace, and used `KeySchedule.SIZE` constants for robust binary parsing in `EpochState`.
- **[STABILITY] E2E Test Hardening**: Added `asyncio.wait_for` guards and updated all test vectors to support the new HPKE context isolation API.

## [0.2.0] - 2026-03-21

### Added
- **Storage Layer**: `AsyncEncryptedStore` using AES-256-GCM for secure, asynchronous persistence of MLS group states.
- **Serialization**: Added `to_bytes` and `from_bytes` methods to `KeySchedule`, `EpochState`, and `MLSGroup` for robust binary snapshots.
- **Key Management**: Enhanced `SignatureKey` and `KemKey` with `private_bytes()` and `from_private_bytes()` to allow secure key-pair persistence within the encrypted store.

### Fixed
- **[CRITICAL] STATE-05 Audit Compliance**: Ensured all private cryptographic materials (sig/kem keys) are stored within a unified, encrypted envelope via AES-GCM to prevent side-channel leaks.

## [0.1.0] - 2026-03-20

### Added
- **Core API**: `MLSGroup` high-level class unifying `RatchetTree`, `EpochState`, and `KeySchedule`.
- **Core Primitives**: Complete implementation of LBBT Math, Data Structures (KeyPackage, LeafNode, ParentNode), and Ed25519/X25519 primitives.
- **Crypto Engine**: `HPKE` Base Mode implementation (rfc9180) for `Welcome` message sealing.
- **E2E Transports**:
  - `test_e2e_websockets.py`: Bidirectional Local testing.
  - `test_e2e_mqtt.py`: Async IoT testing via public pub/sub (`aiomqtt`).
  - `test_e2e_webrtc.py`: Zero-Trust P2P DataChannels (`aiortc`).
  - `test_e2e_grpc.py`: Swarm Backend scaling via `protobuf` and `grpcio`.
- **CI / CD**: 
  - GitHub Actions `.github/workflows/ci.yml` linked and configured with Python 3.12 checks using `uv` and `mypy --strict`.
  - Injected `test_lint.py` to locally enforce Ruff (Sound of Silence) compliance during `pytest` runs.

### Changed
- Refactored the Linter system to ignore `_pb2` binaries and prevent blocking warnings in CI pipelines.
- Applied strict *Sound of Silence* policy via `ruff` (tab indentation, noise removal, unused code purging).
- Translated all internal documentation, tracebacks, and readmes to English standard (`QUAL-04`).

### Fixed
- **[CRITICAL] P0 Crypto Remediation**:
  - `commit_secret` travels encrypted via HPKE for each member instead of plaintext.
  - Ed25519 signature validation on `GroupUpdate` messages to prevent Commit Forgery.
  - `KeySchedule` derivation uses `confirmed_transcript_hash` to mitigate Welcome Spoofing.
  - Safe binary serialization (`to_bytes`/`from_bytes`) replaces vulnerable `pickle` payloads to prevent RCE deserialization across all transports.
  - [RFC 9180] Fixed **HPKE Nonce Reuse (AES-GCM)** implementing `SUITE_ID` derivation (`_labeled_extract`).
  - [RFC 9420] Sub-domain `"MLS 1.0 "` injected into all `KeySchedule` HKDF derivations, including `authentication` label.
  - Enforced strong PFS bounds avoiding premature `WelcomeInfo` symmetric key leaks.
- **[CRITICAL] P1/P2 Audit Remediation**:
  - Unified `KeySchedule` derivation path for Committer and Joiner (`STATE-01`).
  - Fixed transposed `salt/label` arguments in HPKE `_labeled_extract` (`CRYPTO-04`).
  - Added explicit single-use semantics docstring to `HPKE.seal` (`CRYPTO-03`).
  - Mitigated `EpochState` dataclass frozen mutation risk via `__post_init__` RatchetTree deepcopy (`STATE-03`).
- **[CRITICAL] P0 DeepSeek Audit Remediation**:
  - `HPKE.seal` and `open` inject an 8-byte XOR counter into `base_nonce` to eliminate deterministic AES-GCM nonce collision (CVE-2025 Risk).
  - `GroupUpdate` signatures now hash `tree.to_bytes()` and `confirmation_key` to prevent Commit Forgery.
  - `WelcomeInfo` features a length-prefixed `to_bytes` with HMAC integrity verification covering the entire parameter footprint.
- **[CRITICAL] P0/P1 Grok Audit Remediation (Engineering Grade)**:
  - `HPKE._labeled_extract` & `expand` strictly aligned with RFC-9180 Base Mode injecting `"HPKE-v1"` prefix and `SUITE_ID`.
  - `WelcomeInfo` serializes `joiner_index`, eliminating hardcoded positional state desynchronization in `MLSGroup.join()`.
- **[E2E Stability & Certification]**: 
  - Achieved **100.00% Absolute Test Coverage** over cryptography bounds, Tree Math edge-cases, and malformed payload Exceptions.
  - Disabled `AioRpcError` teardown race condition in gRPC ListenWelcomes stream (`E2E-02`).
  - Removed `asyncio` Event race conditions in WebRTC channels.
  - Fixed AESGCM argument assignment (`aad` keyword to positional) detected during E2E websockets.
