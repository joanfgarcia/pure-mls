# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-20

### Added
- **Core API**: `MLSGroup` high-level class unifying `RatchetTree`, `EpochState`, and `KeySchedule`.
- **Core Primitives**: Implementación completa de LBBT Math, Data Structures (KeyPackage, LeafNode, ParentNode), y Ed25519/X25519 primitives.
- **Crypto Engine**: `HPKE` Base Mode implementation (rfc9180) for `Welcome` message sealing.
- **E2E Transports**:
  - `test_e2e_websockets.py`: Bidirectional Local testing.
  - `test_e2e_mqtt.py`: Async IoT testing via public pub/sub (`aiomqtt`).
  - `test_e2e_webrtc.py`: Zero-Trust P2P DataChannels (`aiortc`).
  - `test_e2e_grpc.py`: Swarm Backend scaling via `protobuf` and `grpcio`.
- **CI / CD**: GitHub Actions `.github/workflows/ci.yml` enlazado y configurado con comprobaciones de Python 3.12 usando `uv`.
- **Linter**: Aplicada estricta política *Sound of Silence* mediante `ruff` (indents por tabulaciones, eliminación de ruido).

### Changed
- Refactorizado el sistema de Linter para ignorar binarios `_pb2` e impedir warnings bloqueantes en pipelines CI.

### Fixed
- **[CRITICAL] P0 Crypto Remediation**:
  - `commit_secret` travels encrypted via HPKE for each member instead of plaintext.
  - Ed25519 signature validation on `GroupUpdate` messages to prevent Commit Forgery.
  - `KeySchedule` derivation uses `confirmed_transcript_hash` to mitigate Welcome Spoofing.
  - Safe binary serialization (`to_bytes`/`from_bytes`) replaces vulnerable `pickle` payloads to prevent RCE deserialization across all transports.
  - [RFC 9180] Fixed **HPKE Nonce Reuse (AES-GCM)** implementing `SUITE_ID` derivation (`_labeled_extract`).
  - [RFC 9420] Sub-domain `"MLS 1.0 "` injected into all `KeySchedule` HKDF derivations, including `authentication` label.
  - Enforced strong PFS bounds avoiding prematere `WelcomeInfo` symmetric key leaks.
- **[E2E Stability & Certification]**: 
  - Achieved **100.00% Absolute Test Coverage** over cryptography bounds, Tree Math edge-cases, and malformed payload Exceptions.
  - Removed `asyncio` Event race conditions in WebRTC channels and prevented `AioRpcError` deadlocks in gRPC Streams.
  - Test files formatting strictly compliant with the `"Sound of Silence"` tab-indentation policy.
- Corregida asignación de argumentos de AESGCM (`aad` keyword a posicional) detectada durante E2E websockets.
- Eliminadas `dead variables` y type-hints erróneos detectados por las reglas estrictas Linter de Red Pill.
