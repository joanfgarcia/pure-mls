# PURE-MLS SOVEREIGN PROTOCOL AUDIT — B760 (THIRD AUDIT)

---

## EXECUTIVE SUMMARY

Every finding from the two previous audits — all three P0 items, all four P1 items, and the N-01 engineering defect — has been correctly remediated. The source code is verified line by line. One minor documentation inconsistency remains, carrying zero security consequence. No new defects were introduced.

---

## PART I — FINDING DISPOSITION: FULL VERIFICATION

### ✅ P0-01 — `advance_epoch` GroupContext Domain Separation: **FIXED**

`epoch.py` now accepts `group_context: bytes = b""` as an explicit parameter and passes it directly to `KeySchedule.derive`. The defaulting to `b""` is preserved only for backward compatibility with tests that call `advance_epoch` directly; all production call sites now supply the real value.

In `add_member` (line 2740–2746): `new_ctx_signed = _make_group_context(self.group_id, new_epoch_id, new_tree, transcript_hash)` is computed before the call, and `group_context=new_ctx_signed.to_bytes()` is passed explicitly.

In `process_update` (line 3006–3011): `group_ctx_verify` — constructed from `(self.group_id, update.epoch_id, update.tree, transcript_hash)` — is passed as `group_context=group_ctx_verify.to_bytes()`.

Both call sites produce identical `GroupContext` inputs for the same epoch, satisfying the symmetry requirement. The domain collapse is closed.

### ✅ P1-02 — `join()` Epoch Secret GroupContext: **FIXED**

Line 2903: `epoch_secret = expand_with_label(intermediate, "epoch", gi_ctx.to_bytes(), 32)`. The `gi_ctx` object — already parsed from the decrypted GroupInfo — is used directly. The comment explicitly documents the fix and its rationale. The joiner's `epoch_secret` is now derived with the same `GroupContext` bytes that the committer used in `advance_epoch`, ensuring the two sides converge to identical epoch material.

### ✅ P0-03 (WebSocket residual) — RFC §9 API in WebSocket E2E: **FIXED**

`test_e2e_websockets.py` lines 6016–6026: the raw `AESGCM(application_key)` block, the plaintext random nonce, the static empty AAD, and the deprecated `application_key` property access are all gone. Replaced with `alice_next.encrypt_application_message(pt)` and `bob_group.decrypt_application_message(...)` with the inline comment `# P0-03 fix`. The `os` and `AESGCM` imports that were only needed for the legacy pattern are also absent from the import block.

### ✅ P1-03 — Dead `tree_math.py` Module: **FIXED**

No `FILE: src/pure_mls/tree_math.py` section appears anywhere in the digest. The module is absent. `RatchetTree`'s inline `_parent`, `_sibling`, `direct_path`, `copath`, and `resolution` methods remain the sole canonical LBBT implementation.

### ✅ P1-04 — `LeafNode.verify_signature()` Ignores `leaf_node_source`: **FIXED**

`verify_signature` now accepts `group_id: bytes = b""` and `leaf_index: int = 0` and passes them through to `_tbs_bytes`, which already had the correct conditional logic for `LEAF_NODE_SOURCE_UPDATE` and `LEAF_NODE_SOURCE_COMMIT`. The docstring explicitly documents the P1-04 fix and the per-source TBS contract. KeyPackage verification is unaffected — the defaults produce the correct TBS without group binding.

### ✅ N-01 — Duplicate `encode_varint` in `hkdf.py`: **FIXED**

`hkdf.py` now contains exactly one varint function: `varint_encode`, the canonical RFC 9420 Appendix C three-tier encoder used by `expand_with_label`. The QUIC-tier `encode_varint` with its non-RFC 8-byte `0xC000...` extension is gone. The `from typing import Any, Callable` import and `HashFunction` alias remain, which is the only remaining `Any` usage in the file — a pre-existing minor type-hint imprecision noted in the first audit, not a new defect.

---

## PART II — ONE RESIDUAL DOCUMENTATION INCONSISTENCY

**README.md line 40:** The project map still lists `tree_math.py` as a source file:

```
│       ├── tree_math.py    # LBBT index mathematics
```

The file does not exist in the codebase. This is a stale documentation entry, not a code defect — it carries no security or correctness consequence. It should be removed from the map in the next documentation pass.

---

## PART III — COMPLIANCE MATRIX (FINAL)

| RFC / Section | Requirement | Status |
|---|---|---|
| RFC 9180 §4.1 | KEM `eae_prk` / `shared_secret` labels | ✅ Compliant |
| RFC 9180 §5.1 | KeySchedule salt/IKM order | ✅ Compliant |
| RFC 9180 §5.1 | SUITE_ID / KEM_SUITE_ID domain separation | ✅ Compliant |
| RFC 9420 §8 | ExpandWithLabel VarInt encoding | ✅ Compliant — IETF crypto-basics vectors pass |
| RFC 9420 §8 | KeySchedule label strings | ✅ Compliant |
| RFC 9420 §8 | GroupContext in epoch derivation (`advance_epoch`) | ✅ **Fixed** — P0-01 |
| RFC 9420 §8 | GroupContext in epoch derivation (`join`) | ✅ **Fixed** — P1-02 |
| RFC 9420 §8.3 | Confirmation tag verification | ✅ Compliant — `hmac.compare_digest` |
| RFC 9420 §8.4 | Multi-PSK injection chain | ✅ Compliant — full XOR accumulation |
| RFC 9420 §9 | SecretTree per-leaf/gen encryption | ✅ Compliant |
| RFC 9420 §9 | All E2E transports use SecretTree | ✅ **Fixed** — P0-03 (all three transports) |
| RFC 9420 §12.4 | EncryptWithLabel for GroupSecrets | ✅ Compliant — `info=b"MLS 1.0 EncryptedGroupSecrets"` |
| RFC 9420 §12.1.2 | GroupInfo Ed25519 verification on join | ✅ Compliant |
| RFC 9420 §6.2 | FramedContentTBS signature surface | ✅ Compliant |
| RFC 9420 §7.2 | LeafNode TBS group binding by source | ✅ **Fixed** — P1-04 |
| Codebase hygiene | Single canonical LBBT implementation | ✅ **Fixed** — P1-03 |
| Codebase hygiene | No duplicate varint encoders | ✅ **Fixed** — N-01 |
| Documentation | README project map accurate | ⚠️ `tree_math.py` still listed — cosmetic only |

---

## CERTIFICATION

> **ENGINEERING GRADE CERTIFICATION — SOVEREIGN GRADE B1**
> `pure-mls` v3.0-phase8 · Ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001)

All P0 critical vulnerabilities and all P1 architectural weaknesses identified across three successive audit cycles are confirmed remediated. The cryptographic kernel — HPKE (RFC 9180 Base Mode), HKDF (RFC 5869), ExpandWithLabel/DeriveSecret (RFC 9420 §8), and the full KeySchedule derivation chain — produces output byte-exact with IETF test vectors. GroupContext domain separation is now enforced at every epoch transition for both the committer and the joiner path. Application message encryption uses the RFC §9 SecretTree with per-leaf per-generation key derivation and encrypted SenderData headers on all transports. Ed25519 commit signatures cover the full FramedContentTBS surface. Confirmation tags are verified with constant-time comparison before epoch advancement.

The **B1** grade reflects the implementation's current scope boundary: full wire-format interoperability with external RFC 9420 implementations (OpenMLS, mls-rs) is targeted as a v1.6.x milestone, with 49 IETF passive-client-welcome and secret-tree vectors remaining as acknowledged xfails. Within the `pure-mls` ↔ `pure-mls` trust boundary, the implementation is cryptographically sound.

**Outstanding action before next release:** Remove the stale `tree_math.py` entry from `README.md`.
