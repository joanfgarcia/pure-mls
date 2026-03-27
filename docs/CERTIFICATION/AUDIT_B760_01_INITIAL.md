# PURE-MLS SOVEREIGN PROTOCOL AUDIT — B760
### Cryptography Auditor Grade: **CONDITIONAL PASS with P0 Blocking Defects**

---

## EXECUTIVE SUMMARY

`pure-mls` is a technically ambitious, well-structured implementation. The HPKE primitive layer (`hpke.py`), HKDF plumbing (`hkdf.py`), and Ed25519/X25519 key separation (`keys.py`) are correctly implemented and pass the RFC 5869 / RFC 9180 vectors cited in the changelog. The key schedule derivation chain (`keyschedule.py`) is label-correct per OpenMLS cross-validation. The tree math (`tree_math.py` and `RatchetTree` inline methods) is structurally sound.

However, **three P0 vulnerabilities and four P1 weaknesses** prevent certification. They are ordered by severity below.

---

## PART I — CRITICAL VULNERABILITIES (P0)

### P0-01 · `advance_epoch` Hardcodes `group_context=b""` — Key Schedule Domain Collapse

**Severity:** P0 — Full epoch key recovery / state desynchronization between any `pure-mls` group and any RFC 9420-compliant external peer.

**Location:** `src/pure_mls/epoch.py`, line 1465–1468.

```python
# CURRENT — DEFECTIVE
next_schedule = KeySchedule.derive(
    init_secret=self.key_schedule.init_secret,
    commit_secret=commit_secret,
    group_context=b"",   # ← HARDCODED EMPTY — RFC VIOLATION
)
```

**Root Cause:** RFC 9420 §8 mandates that both `joiner_secret` and `epoch_secret` are derived with the TLS-encoded `GroupContext` as the `ExpandWithLabel` context parameter. `GroupContext` encodes `group_id`, `epoch`, `tree_hash`, and `confirmed_transcript_hash`. By collapsing it to `b""`, all groups with different IDs but the same `(init_secret, commit_secret)` pair will produce **identical epoch secrets** — total domain collapse.

The code acknowledges this with its own comment: *"Note: group_context = b'' for pure-mls internal groups (consistent approximation)."* That comment is a confession of non-compliance, not a justification. The "consistent approximation" argument holds only when both sides are `pure-mls` clients with the same bug. Any mixed-implementation group would silently desynchronize.

The `join()` path partially contradicts this — it reconstructs the joiner's epoch secret using `b""` context explicitly, and then cross-references a note that *"IETF interop join would use `gi_ctx.to_bytes()`"*. This is a bifurcated code path with only one correct branch.

**Fix:**

```python
def advance_epoch(
    self,
    commit_secret: bytes,
    next_tree: RatchetTree,
    transcript_hash: bytes = b"",
) -> "EpochState":
    next_epoch_id = self.epoch_id + 1
    tree_hash = hashlib.sha256(next_tree.to_bytes()).digest()
    group_ctx = GroupContext(
        group_id=self.group_id,
        epoch=next_epoch_id,
        tree_hash=tree_hash,
        confirmed_transcript_hash=transcript_hash,
    )
    next_schedule = KeySchedule.derive(
        init_secret=self.key_schedule.init_secret,
        commit_secret=commit_secret,
        group_context=group_ctx.to_bytes(),
    )
    return EpochState(
        group_id=self.group_id,
        epoch_id=next_epoch_id,
        tree=next_tree,
        key_schedule=next_schedule,
    )
```

The `join()` path at line 2808–2810 must receive the same fix: replace `b""` with `gi_ctx.to_bytes()` unconditionally, removing the conditional comment.

---

### P0-02 · `confirmation_tag` Not Verified on `process_update` — Commit Forgery Vector

**Severity:** P0 — A forged commit carrying a valid signature but incorrect `joiner_secret` or tampered tree bytes will be accepted without HMAC validation of the confirmation tag.

**Location:** `src/pure_mls/group.py`, lines 2915–2921.

```python
# CURRENT — TAG COMPUTED BUT NEVER VERIFIED
_conf_tag = hmac.new(next_state.key_schedule.confirmation_key, transcript_hash, "sha256").digest()
# NOTE: constant-time tag comparison against the sender's tag would require the
# full PublicMessage wire format — deferred to Phase 7 wire-format alignment.
_ = _conf_tag  # prevent unused-variable lint; used by callers via key_schedule
```

The comment *"deferred to Phase 7"* is an open security door. RFC 9420 §8.3 mandates that every member verify the `confirmation_tag` in the Commit's `FramedContentAuthData` before advancing the epoch. The tag is `HMAC(confirmation_key, confirmed_transcript_hash)` and is the **only cryptographic proof that the committer derived the same `epoch_secret`**. Without this check, an adversary who can forge or replay a valid Ed25519 signature (e.g., via a re-used nonce in a different context) may advance a victim's epoch to a desynchronized state.

`PublicMessage` does carry `confirmation_tag` in `auth.confirmation_tag` (verified to be 32 bytes in the test suite). The wire format is already parsed. The verification path exists — it is simply not called.

**Fix:**

```python
# In process_update(), after computing _conf_tag:
expected_tag = _conf_tag  # HMAC(new confirmation_key, transcript_hash)

# update._group_ctx carries the sender's confirmation_tag from PublicMessage
# If called via the raw GroupUpdate path, require the tag to be present.
if not update._confirmation_tag:
    raise ValueError("Missing confirmation_tag in GroupUpdate — cannot verify commit")

if not hmac.compare_digest(expected_tag, update._confirmation_tag):
    raise ValueError("Confirmation tag mismatch — epoch desynchronization or replay attack")
```

`hmac.compare_digest` is mandatory here — the tag is 32 bytes of secret-derived MAC material. Any non-constant-time comparison (`==`, `bytes.__eq__`) creates a timing oracle.

---

### P0-03 · Transport E2E Tests Bypass the MLS Layer with Raw `AESGCM(application_key)` — MQTT and WebRTC

**Severity:** P0 — In `test_e2e_mqtt.py` (lines 5640–5646) and `test_e2e_webrtc.py` (lines 5798–5804), Alice and Bob encrypt and decrypt application messages using `AESGCM(alice_group.application_key)` with a static AAD `b"sender_bob"` and a **randomly generated nonce sent in plaintext alongside the ciphertext** over the wire.

```python
# test_e2e_mqtt.py — DEFECTIVE PATTERN
aes = AESGCM(alice_group.application_key)
nonce = os.urandom(12)
ct = aes.encrypt(nonce, reading, b"sender_bob")
data_msg = {"type": "app_data", "nonce": base64.b64encode(nonce).decode(), "ct": ...}
```

This is not an MLS PrivateMessage. It has four compound flaws:

1. **`application_key` is deprecated** — `group.py` emits a `DeprecationWarning` on access. The API has been superseded by `encrypt_application_message()` which uses the RFC 9420 §9 SecretTree. These tests call the deprecated path, meaning they test a non-functional protocol surface.
2. **Random nonce transmitted in plaintext** — GCM nonce reuse is catastrophic (full plaintext recovery from two ciphertexts). The random nonce is sent as a JSON field, giving a passive observer everything needed if nonce collision ever occurs across retransmissions or replays.
3. **Static AAD `b"sender_bob"`** — the AAD must bind to `(group_id, epoch_id)` per RFC §9.2 to prevent cross-epoch and cross-group replay. A ciphertext from epoch 1 is valid AAD under epoch 2 with this implementation.
4. **No SenderData header** — the RFC §9 SecretTree and SenderData encryption are entirely skipped. Sender identity is plaintext in the JSON body.

**Fix:** Replace the raw AESGCM block in both E2E tests with the existing compliant API:

```python
# CORRECT
ciphertext = alice_group.encrypt_application_message(reading)
# ... transmit ciphertext bytes ...
plaintext = bob_group.decrypt_application_message(ciphertext)
```

The `encrypt_application_message` / `decrypt_application_message` pair in `group.py` is correctly implemented with the SecretTree, per-leaf generation advancement, SenderData HPKE encryption, and epoch-bound AAD. The E2E tests must use it.

---

## PART II — ARCHITECTURAL WEAKNESSES (P1)

### P1-01 · `HPKE.seal` for `EncryptedGroupSecrets` Uses `info=b""` — RFC 9420 §12.4 Violation

**Location:** `group.py` line 2684–2686.

```python
gs_enc, gs_ct = HPKE.seal(
    key_package.init_key_pub,
    group_secrets.to_bytes(),
    info=b"",  # RFC §12.1.2: no additional info for EncryptedGroupSecrets
)
```

RFC 9420 §12.4 specifies a distinct `EncryptWithLabel` context for `EncryptedGroupSecrets`:
`info = EncryptWithLabel(label="MLS 1.0 Welcome", context=GroupInfoTBS_or_KPRef)`.

Passing `info=b""` omits the domain label entirely. This collapses the HPKE context for GroupSecrets encryption to the same domain as any other `HPKE.seal(info=b"")` call in the system. While the HPKE SUITE_ID (`HPKE\x00\x20\x00\x01\x00\x01`) still domain-separates from non-HPKE contexts, there is no label distinguishing a Welcome GroupSecrets encapsulation from a TreeKEM path-secret encapsulation that also passes `info=group_ctx.to_bytes()` on a key that happens to match. The CHANGELOG acknowledges this was previously more broken (`info=b""` is called "compliant" at line 2686) but RFC 9420 §12.4 is unambiguous: the `EncryptWithLabel` wrapper is mandatory.

---

### P1-02 · `join()` Epoch Secret Derivation Uses `b""` GroupContext — Same Root as P0-01

**Location:** `group.py` lines 2808–2810.

```python
psk_zeros = b"\x00" * 32
intermediate = hkdf_extract(gs.joiner_secret, psk_zeros)
epoch_secret = expand_with_label(intermediate, "epoch", b"", 32)
```

The inline comment confirms awareness: *"NOTE: pure-mls Welcome doesn't carry a TLS GroupContext, so we use b'' to match alice's advance_epoch() which also uses b''. IETF interop join would use gi_ctx.to_bytes()."*

This is the joiner-side mirror of P0-01. Once P0-01 is fixed to pass real GroupContext into `advance_epoch`, this path must be fixed in lockstep or joiner and committer will produce different `epoch_secret` values and desynchronize immediately. The `gi_ctx` object is already parsed at this point in `join()` — it must be used.

---

### P1-03 · `tree_math.py` Duplicate Implementation — Silent Divergence Risk

**Location:** `src/pure_mls/tree_math.py` (standalone module) vs. `RatchetTree._parent()`, `RatchetTree._sibling()`, `RatchetTree.direct_path()`, `RatchetTree.copath()` (inline methods, `tree.py` lines 4634–4693).

Two independent implementations of LBBT arithmetic exist side by side. `tree_math.py` is imported nowhere in the production code path — `group.py`'s `process_update()` calls `update.tree.direct_path()` and `update.tree.copath()`, which are the inline `RatchetTree` methods. `tree_math.py` is dead production code. This creates a silent divergence risk: a future fix in one implementation will not propagate to the other, and there are no cross-validation tests between them.

**Fix:** Delete `tree_math.py` or promote it as the single canonical source and delegate all `RatchetTree` tree-math methods to it. Do not maintain two copies.

---

### P1-04 · `LeafNode.verify_signature()` Calls `_tbs_bytes()` Without `group_id` / `leaf_index` — Incorrect TBS for Non-`key_package` Sources

**Location:** `tree.py`, line 4300.

```python
def verify_signature(self) -> None:
    ...
    pub.verify(self.signature, self._tbs_bytes())  # ← always uses group_id=b"", leaf_index=0
```

`_tbs_bytes()` with no arguments produces the TBS for a `LEAF_NODE_SOURCE_KEY_PACKAGE` leaf (no group binding). For `LEAF_NODE_SOURCE_UPDATE` or `LEAF_NODE_SOURCE_COMMIT` leaves, the TBS must include `group_id` and `leaf_index` per RFC 9420 §7.2. Calling `verify_signature()` on an Update or Commit leaf node will verify a **different byte string** than what was signed, producing a silent false-positive verification on any structurally valid signature over the wrong data. The verifier should require the caller to supply `group_id` and `leaf_index` when `leaf_node_source != KEY_PACKAGE`.

---

## PART III — ENGINEERING POLICY: SOUND OF SILENCE AUDIT

### Type Hinting (PEP 484)
**Status: Partial.** `hkdf.py` uses `HashFunction = Callable[[], Any]` — `Any` in the return type is a policy violation per the project's own manifesto ("Any is an admission of defeat"). The correct type is `Callable[[], hashlib._Hash]` or a `Protocol`. `group.py` has several internal helper functions (`_transcript_hash`, `_make_group_context`, `_make_kp_ref`) whose return types are present but whose parameter type annotations are incomplete (missing `sender_index: int` annotation in the `_transcript_hash` signature at point of usage).

### Indentation
**Status: Compliant.** All production source files use tab indentation throughout. No violations detected.

### Dead Code
**Status: Non-compliant.** `tree_math.py` is a complete dead module — zero imports in the production call graph. Additionally, `KeyPackage.leaf_node_signature` is a legacy field explicitly marked "kept for legacy compat" but is written to in `KeyPackage.create()` (line 4451) and never read in any verification path. It is live-dead: written but semantically orphaned. Both should be removed or formally delegated.

### Branch Coverage
**Status: Not independently verifiable** from the digest. The CHANGELOG reports `146 passed, 0 failed` in the latest run. However, the P0 branches identified above — confirmation tag verification in `process_update`, GroupContext in `advance_epoch` — have no negative tests (tests that confirm a forged tag or mismatched GroupContext causes rejection). The test suite validates the happy path exhaustively; adversarial path coverage is absent for the most critical branches.

---

## PART IV — COMPLIANCE MATRIX

| RFC / Section | Requirement | Status | Notes |
|---|---|---|---|
| RFC 9180 §4.1 | KEM `eae_prk` / `shared_secret` labels | ✅ Compliant | Fixed in phase8 changelog |
| RFC 9180 §5.1 | KeySchedule salt/IKM order | ✅ Compliant | Fixed in phase8 |
| RFC 9180 §5.1 | SUITE_ID domain separation | ✅ Compliant | Distinct KEM_SUITE_ID vs SUITE_ID |
| RFC 9420 §8 | ExpandWithLabel VarInt encoding | ✅ Compliant | Phase6 fix, IETF vectors pass |
| RFC 9420 §8 | KeySchedule label strings | ✅ Compliant | `confirm`, `sender data`, `authentication` verified |
| RFC 9420 §8 | GroupContext in epoch derivation | ❌ **P0-01** | Hardcoded `b""` |
| RFC 9420 §8.3 | Confirmation tag verification | ❌ **P0-02** | Computed, never verified |
| RFC 9420 §9 | SecretTree per-leaf/gen encryption | ✅ Compliant | Core path correct |
| RFC 9420 §9 | E2E tests use SecretTree | ❌ **P0-03** | MQTT/WebRTC bypass to raw AESGCM |
| RFC 9420 §12.4 | EncryptWithLabel for GroupSecrets | ⚠️ **P1-01** | `info=b""` omits domain label |
| RFC 9420 §7.2 | LeafNode TBS includes group binding | ⚠️ **P1-04** | `verify_signature()` ignores source |
| RFC 9420 §12.1.2 | GroupInfo Ed25519 verification | ✅ Compliant | `join()` verifies committer key |
| RFC 9420 §6 | FramedContentTBS signature surface | ✅ Compliant | Full TBS constructed in `add_member` / `process_update` |
| RFC 5869 | HKDF-Extract / HKDF-Expand | ✅ Compliant | RFC 5869 TC1–TC3 pass |

---

## CERTIFICATION DECISION

> **CERTIFICATION WITHHELD.**
