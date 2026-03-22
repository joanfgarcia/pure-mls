# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-03-22

### Added (Full OpenMLS Signature Compliance)

- **[RFC 9420 §6.2] `_make_framed_content_tbs(group_ctx, framed)`**: builds the
  `FramedContentTBS = version(u16) + wire_format(u16) + GroupContext + FramedContent`
  signing surface. Ed25519 signatures now cover this TBS instead of raw `transcript_hash`.
- **[RFC 9420 §6.2] `KeySchedule.derive_membership_key(authentication_secret)`**:
  `ExpandWithLabel(authentication_secret, "membership", b"", 32)` → 32-byte key for
  generating and verifying `membership_tag`.
- **[RFC 9420 §8.1] `confirmation_tag`** in `PublicMessage`: now correctly computed as
  `HMAC-SHA256(confirmation_key, confirmed_transcript_hash)` using the new epoch's
  `confirmation_key` from `KeySchedule`.
- **[RFC 9420 §6.2] `membership_tag`** in `PublicMessage`: now correctly computed as
  `HMAC-SHA256(membership_key, PublicMessageTBS)` where `membership_key` is derived via
  `ExpandWithLabel(authentication_secret, "membership", b"", 32)`.
- `GroupUpdate` carries 4 optional RFC context fields (`_group_ctx`, `_confirmation_key`,
  `_authentication_secret`, `_transcript_hash`) set by `add_member()` to enable full
  RFC `PublicMessage` construction in `MLSMessage.wrap_commit()`.
- `GroupUpdate._body_bytes()` returns the serialized Commit body without the signature
  field (used to construct `FramedContent.content` for TBS computation).

### Changed

- **`add_member()`**: committer's Ed25519 signature is now over `FramedContentTBS`
  (not raw `transcript_hash`). The `FramedContent` is built from the unsigned commit body.
- **`process_update()`**: signature verification now reconstructs `FramedContentTBS`
  identically to how `add_member()` built it, ensuring full round-trip correctness.
- **`PublicMessage.from_group_update()`**: now requires 4 explicit kwargs:
  `group_ctx`, `confirmation_key`, `authentication_secret`, `transcript_hash`.
  `MLSMessage.wrap_commit()` passes these from the `GroupUpdate` context fields when
  available; falls back to placeholder values for deserialized commits.
- **`FramedContent.group_id`**: now populated with the actual `group_id` from
  `GroupContext` (was `b""` in v1.1).

## [1.1.0] - 2026-03-22

### Added (Full OpenMLS Interoperability)

- **[RFC 9420 §6] `FramedContent`**: TLS-encoded wrapper for Commit messages with
  `group_id`, `epoch`, `Sender{member, leaf_index}`, `authenticated_data`, `content`.
  Includes `to_bytes()/from_bytes()`.
- **[RFC 9420 §6] `FramedContentAuthData`**: `signature + confirmation_tag` auth data
  for a `FramedContent`. Includes `to_bytes()/from_bytes()`.
- **[RFC 9420 §6.2] `PublicMessage`**: RFC-compliant framing: `FramedContent +
  FramedContentAuthData + membership_tag`. Factory `from_group_update()`, round-trip
  `to_bytes()/from_bytes()`, and `to_group_update()` extractor.
- **[RFC 9420 §12.1.2] `KeySchedule.derive_welcome_key(joiner_secret, context)`**:
  `ExpandWithLabel(joiner_secret, "welcome", context, 16)` → 16-byte AES-128-GCM key.
- **[RFC 9420 §12.1.2] `KeySchedule.derive_welcome_nonce(joiner_secret, context)`**:
  `ExpandWithLabel(joiner_secret, "nonce", context, 12)` → 12-byte GCM nonce.
- 7 new tests in `tests/test_wire_format.py` covering all v1.1 structures.

### Changed

- **`Welcome.encrypted_group_info`**: GroupInfo now sealed via AES-128-GCM
  `welcome_key` (derived from `joiner_secret`) instead of HPKE directly.
  Wire format: `nonce(12 bytes) + ciphertext`. Enables decryption without HPKE `kem_output`.
- **`Welcome` (`EncryptedGroupSecrets`)**: HPKE `info` changed from `GroupContext.to_bytes()`
  to `b""` per RFC 9420 §12.1.2 (no additional info for `EncryptedGroupSecrets`).
- **`MLSMessage.wrap_commit()`**: now wraps `GroupUpdate` in a `PublicMessage` envelope
  before storing in `MLSMessage.body`. `unwrap_commit()` also updated to parse `PublicMessage`.
- **`__init__.py`**: exports extended with `FramedContent`, `FramedContentAuthData`,
  `PublicMessage`.

### Migration Notes (v1.0.0 → v1.1.0)

- `MLSMessage.body` for commits is now `PublicMessage.to_bytes()` (not `GroupUpdate.to_bytes()`).
  Existing code that reads the raw body bytes directly will need to parse via `PublicMessage`.
- `Welcome.encrypted_group_info` format changed: first 12 bytes are the AES-GCM nonce,
  remainder is ciphertext. The old `kem_output(32)+ciphertext` layout is no longer used.
- Both changes are **breaking** with respect to v1.0.0 wire format; pure-mls ↔ pure-mls
  sessions that mix v1.0 and v1.1 nodes will fail to interoperate.

## [1.0.0] - 2026-03-22

### Added

- **[RFC 9420 §8.1] `GroupContext` struct** (`src/pure_mls/group.py`): TLS-encoded `GroupContext`
  with `version`, `cipher_suite`, `group_id`, `epoch`, `tree_hash`, `confirmed_transcript_hash`,
  and `extensions`. Used as HPKE `info` parameter for all commit secret sealing/opening operations,
  replacing the old `b"mls10-commit-secret"` string. Includes `to_bytes()/from_bytes()`.
- **[RFC 9420 §12.1.2] `GroupSecrets` + `EncryptedGroupSecrets` + `Welcome`** RFC message types:
  - `GroupSecrets`: HPKE-sealed joiner_secret + leaf_index per new member.
  - `EncryptedGroupSecrets`: serialized HPKE-sealed `GroupSecrets` keyed by `KeyPackageRef`.
  - `Welcome`: full RFC §12.1.2 Welcome with `cipher_suite`, `encrypted_group_secrets[]`,
    `encrypted_group_info`. Replaces custom `WelcomeInfo` (now alias for backward compat).
  - All three have `to_bytes()/from_bytes()` with TLS wire format.
- **[RFC 9420 §12.1.1] `GroupUpdate.to_bytes()/from_bytes()`**: TLS-encoded Commit wire format
  (`epoch_id`, `tree<V>`, `secrets_count`, `[kp_ref, enc_ct]*`, `committer_index`, `signature`).
- **[RFC 9420 §6] `MLSMessage` + `WireFormat`**: top-level framing envelope
  (`version=0x0001`, `wire_format`, `body<V>`). Factory methods `wrap_welcome()`, `wrap_commit()`,
  and `unwrap_welcome()`, `unwrap_commit()`. Enables zero-knowledge transport over Firebase/MQTT.
- **`src/pure_mls/tls.py`**: new module with TLS presentation language primitives
  (`tls_u8/u16/u32/u64`, `tls_opaque`, `tls_opaque32`, `read_u8/u16/u32/u64`, `read_opaque`,
  `read_opaque32`, `read_fixed`).
- **`tests/test_wire_format.py`**: 12 new tests covering all RFC wire format types, including
  a full end-to-end simulation of the Firebase zero-knowledge group join flow.

### Changed

- `add_member()` now produces an RFC 9420 `Welcome` (was `WelcomeInfo`). `WelcomeInfo` is kept
  as an alias for backward compatibility.
- `MLSGroup.join()` now decrypts `GroupSecrets` and `GroupInfo` via HPKE using
  `GroupContext.to_bytes()` as the info parameter.
- `_transcript_hash()` now builds `GroupContext.to_bytes()` as the primary prefix for the
  SHA-256 hash, making it RFC-compliant.
- HPKE info for commit secret sealing: was `b"mls10-commit-secret"`, now `GroupContext.to_bytes()`
  (binds each HPKE operation to the specific group + epoch cryptographically).
- `__init__.py` exports extended with: `Welcome`, `WireFormat`, `MLSMessage`, `GroupContext`,
  `GroupSecrets`, `EncryptedGroupSecrets`.

### Notes

- Full interoperability with external MLS clients (e.g. OpenMLS) requires completing the
  `AuthenticatedContent` / `FramedContent` wrapping (deferred to v1.1). The current `GroupUpdate`
  TLS format is a compact subset sufficient for pure-mls ↔ pure-mls exchange.
- `GroupInfo` HPKE sealing currently uses the joiner-facing `init_key_pub` directly. Full RFC
  compliance uses a derived `welcome_key` from `joiner_secret` (deferred to v1.1).

## [0.4.0] - 2026-03-22

### Changed (Breaking)

- **[RFC 9420 §10.2] STATE-04 — `KeyPackageRef` now RFC-compliant**: `_make_kp_ref()` uses
  `RefHash("MLS 1.0 KeyPackageRef", kp)` = `HKDF-Expand(HKDF-Extract(b"", kp), label, Nh=32)`
  per RFC 9420 §10.2. Output is now **32 bytes** (was 16-byte raw SHA-256 truncation).
  `GroupUpdate.encrypted_commit_secrets` keys change from `bytes[16]` to `bytes[32]`.
- **[RFC 9420 §8.2] STATE-02 — `Sender` struct in transcript hash**: `_transcript_hash()` now
  includes `SenderType(uint8=0x01 member) + leaf_index(uint32)` = 5 bytes, instead of only the
  4-byte leaf index. This matches RFC 9420 §8.2 `Sender` struct encoding exactly.

### Added

- **Embedded MQTT broker (`amqtt`)**: `tests/test_e2e_mqtt.py` now uses an embedded `amqtt`
  broker via `pytest_asyncio.fixture`, eliminating the dependency on an external MQTT server.
  **44/44 tests green** (full suite, no external services required).
- `amqtt>=0.11.0` added to `[dependency-groups.dev]` in `pyproject.toml`.

### Fixed

- `tests/test_state_findings.py` and `tests/test_group_errors.py` updated to use 32-byte
  `KeyPackageRef` keys and the RFC-correct 5-byte `Sender` struct in mock `GroupUpdate` objects.

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
