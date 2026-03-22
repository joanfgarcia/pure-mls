# Certification Status Note — v0.3.0 to v0.4.0

This document tracks the compliance improvements made after the Engineering Grade
Certification issued for v0.2.3.

## Post-Certification Changes (v0.3.0)

The v0.3.0 release addressed the two open audit findings from the v0.2.3 certification:

| Finding | Resolution | Version |
|---|---|---|
| STATE-02 (transcript hash incomplete) | Implemented `_transcript_hash()` covering group_id, cipher_suite, epoch, tree, confirmation_key, ciphertexts, extensions, and sender | v0.3.0 |
| STATE-04 (KeyPackageRef missing) | Implemented `KeyPackageRef` keying for `encrypted_commit_secrets` | v0.3.0 |

> [!WARNING]
> The STATE-02 and STATE-04 implementations in v0.3.0 were **simplified approximations**,
> not fully RFC-compliant. They were corrected in v0.4.0.

## Post-Certification Changes (v0.4.0)

| Issue | v0.3.0 (incorrect) | v0.4.0 (RFC-correct) |
|---|---|---|
| `KeyPackageRef` (RFC §10.2) | `SHA-256(kp)[:16]` — raw, truncated | `RefHash("MLS 1.0 KeyPackageRef", kp)` = labeled HKDF-Expand, 32 bytes |
| `Sender` struct (RFC §8.2) | `leaf_index.to_bytes(4)` only | `SenderType(0x01) + leaf_index.to_bytes(4)` — 5 bytes |
| MQTT test | External broker required | Embedded `amqtt` broker (44/44 tests green, no external deps) |

## Current Compliance Status (v0.4.0)

**44/44 tests green. No external services required.**

See `docs/02_ARCHITECTURE.md §4` for full RFC compliance table.

### Remaining v1.0 items (not blocking Engineering Grade)

- RFC §11: HPKE path secret info = `GroupContext` (currently `b"mls10-commit-secret"`)
- RFC §12: TLS-style wire format for `Welcome`, `Commit`, `MLSMessage`

> [!NOTE]
> A new full Engineering Grade Audit is recommended after v1.0 to certify interoperability
> with other RFC 9420 implementations (e.g., OpenMLS).
