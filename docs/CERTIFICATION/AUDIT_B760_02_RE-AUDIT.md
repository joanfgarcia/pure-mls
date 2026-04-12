# PURE-MLS SOVEREIGN PROTOCOL AUDIT — B760 (RE-AUDIT)

---

## PRELIMINARY: FINDING DISPOSITION MATRIX

Before the detailed analysis, here is the definitive status of every finding from the previous audit:

| ID | Previous Finding | Disposition |
|---|---|---|
| P0-01 | `advance_epoch` hardcodes `group_context=b""` | ❌ **NOT FIXED** |
| P0-02 | `confirmation_tag` never verified in `process_update` | ✅ **FIXED** |
| P0-03 | E2E transports bypass MLS layer with raw AESGCM | ✅ **FIXED** (MQTT, WebRTC) / ⚠️ **NEW INSTANCE** (WebSockets) |
| P1-01 | `info=b""` on `EncryptedGroupSecrets` HPKE seal | ✅ **FIXED** |
| P1-02 | `join()` epoch secret uses `b""` GroupContext | ❌ **NOT FIXED** |
| P1-03 | `tree_math.py` dead duplicate module | ❌ **NOT FIXED** |
| P1-04 | `LeafNode.verify_signature()` ignores source type | ❌ **NOT FIXED** |

Additionally, one new engineering defect has been introduced: a **duplicate varint function** in `hkdf.py`.

---

## PART I — OUTSTANDING CRITICAL VULNERABILITIES (P0)

### P0-01 · `advance_epoch` Still Hardcodes `group_context=b""` — **UNCHANGED**

**Location:** `src/pure_mls/epoch.py`, lines 1507–1511.

The code is byte-for-byte identical to what was flagged in the previous audit:

```python
next_schedule = KeySchedule.derive(
    init_secret=self.key_schedule.init_secret,
    commit_secret=commit_secret,
    group_context=b"",  # consistent for pure-mls ↔ pure-mls; IETF join uses real GC
)
```

The comment — *"consistent for pure-mls ↔ pure-mls; IETF join uses real GC"* — was not removed, not amended, and not addressed. The `transcript_hash` parameter is accepted by `advance_epoch` and correctly propagated to the `EpochState` constructor, but it is **never passed to `KeySchedule.derive`**. The RFC 9420 §8 GroupContext domain separation remains absent from all epoch transitions.

This is a confirmed carry-over of the highest-severity finding. It continues to mean that any two groups sharing the same `(init_secret, commit_secret)` values will derive identical `epoch_secret`, `encryption_secret`, `confirmation_key`, and all other epoch material regardless of their `group_id`, `epoch`, or `tree_hash`. The GroupContext binding — the primary mechanism that makes epoch keys group-specific — does not exist in this implementation.

The CHANGELOG entry for this submission (`Fixed (B760 Audit — Minor Findings)`) does not mention P0-01 at all, confirming it was not attempted.

---

### P0-03 (Residual) · `test_e2e_websockets.py` Still Uses Raw `AESGCM(application_key)` With Plaintext Nonce

**Location:** `tests/test_e2e_websockets.py`, lines 5989–6009.

The MQTT and WebRTC transports were correctly migrated to `encrypt_application_message` / `decrypt_application_message`. The WebSocket test was not. It retains all four original defects:

```python
app_key_alice = alice_next.application_key  # deprecated property
aes_alice = AESGCM(app_key_alice)
nonce = os.urandom(12)                      # random nonce sent in plaintext
ct = aes_alice.encrypt(nonce, pt, b"")      # no epoch-bound AAD, no SenderData
```

This is the original P0-03 pattern: deprecated raw key access, cleartext nonce in the JSON payload, static empty AAD, and no RFC §9 SecretTree. The test will emit a `DeprecationWarning` on the `application_key` access. The CHANGELOG entry claims the deprecation warnings were *"eliminated"* — that is true for `test_group.py` and `test_state_findings.py`, but not for this test. The fix is a single substitution:

```python
# REPLACE the data-plane block in test_mls_websockets_e2e with:
ct_bytes = alice_next.encrypt_application_message(pt)
await alice_ws.send(json.dumps({"type": "app_message", "payload": base64.b64encode(ct_bytes).decode()}))

chat_msg = json.loads(await bob_ws.recv())
decrypted = bob_group.decrypt_application_message(base64.b64decode(chat_msg["payload"]))
assert decrypted == pt
```

---

## PART II — OUTSTANDING ARCHITECTURAL WEAKNESSES (P1)

### P1-02 · `join()` Epoch Secret Still Uses `b""` GroupContext — **UNCHANGED**

**Location:** `group.py`, lines 2854–2858.

```python
# NOTE: pure-mls Welcome doesn't carry a TLS GroupContext, so we use b"" to match
# alice's advance_epoch() which also uses b"". IETF interop join would use gi_ctx.to_bytes().
psk_zeros = b"\x00" * 32
intermediate = hkdf_extract(gs.joiner_secret, psk_zeros)
epoch_secret = expand_with_label(intermediate, "epoch", b"", 32)
```

This is the joiner-side mirror of P0-01, noted explicitly in the previous audit as a mandatory co-fix. It was not addressed. Critically, the comment itself says *"IETF interop join would use `gi_ctx.to_bytes()`"* — `gi_ctx` is already parsed and available at this point in the function. Fixing P0-01 and this finding is the same two-line change applied to two call sites.

### P1-03 · `tree_math.py` Dead Duplicate Module — **UNCHANGED**

**Location:** `src/pure_mls/tree_math.py`.

The module is still present in the file map (line 40 of the README). There are no imports of it in `group.py`, `epoch.py`, or any other production module. The `RatchetTree` inline methods (`_parent`, `_sibling`, `direct_path`, `copath`) continue to be the live implementation. Two independent LBBT implementations with no cross-validation between them remain in the codebase, in direct violation of the Sound of Silence dead-code policy.

### P1-04 · `LeafNode.verify_signature()` Ignores `leaf_node_source` — **UNCHANGED**

**Location:** `tree.py`, `verify_signature()` method.

The method still calls `self._tbs_bytes()` with no arguments unconditionally, producing the `key_package`-source TBS regardless of whether the leaf was signed as `update` or `commit` source. Any `LeafNode` with `leaf_node_source != 0x01` whose signature was computed over a TBS that included `group_id` and `leaf_index` will have its signature incorrectly verified against a TBS that excludes them — a silent false-positive for Update and Commit leaves.

---

## PART III — NEW DEFECT INTRODUCED IN THIS REVISION

### N-01 · `hkdf.py` — Duplicate Varint Encoding Functions (Dead Code / Silent Divergence)

**Location:** `src/pure_mls/hkdf.py`, lines 3076–3115.

The new digest introduces a second varint function, `encode_varint`, alongside the existing `varint_encode`:

```python
def encode_varint(val: int) -> bytes:
    """QUIC-style variable-length integer encoding (RFC 9000)."""
    if val <= 0x3F:        return bytes([val])
    if val <= 0x3FFF:      return (0x4000 | val).to_bytes(2, "big")
    if val <= 0x3FFFFFFF:  return (0x80000000 | val).to_bytes(4, "big")
    if val <= 0x3FFFFFFFFFFFFFFF:
        return (0xC000000000000000 | val).to_bytes(8, "big")
    raise ValueError(...)

def varint_encode(n: int) -> bytes:  # the original, used by expand_with_label
    """MLS variable-length integer encoding (RFC 9420 §C / mls-rs-codec VarInt)."""
    if n <= 63:          return bytes([n])
    elif n <= 16383:     return ((n | 0x4000) & 0xFFFF).to_bytes(2, "big")
    elif n <= (1 << 30) - 1:
        return ((n | 0x80000000) & 0xFFFFFFFF).to_bytes(4, "big")
    else: raise ValueError(...)
```

`encode_varint` supports an 8-byte encoding tier (`0xC0...` prefix) that `varint_encode` does not. RFC 9420 Appendix C defines only a 4-tier VarInt (0..2^30−1); the 8-byte QUIC extension is not part of the MLS VarInt specification. The two functions produce identical output for the values actually used in MLS (all label lengths and context lengths fit in 1 byte), but their presence creates ambiguity about which is canonical, and `encode_varint` is entirely unreferenced — `expand_with_label` calls `varint_encode`. This is exactly the dual-implementation pattern flagged in P1-03 for `tree_math.py`: a silent dead copy that will cause confusion in future maintenance. It must be deleted.

---

## PART IV — ACKNOWLEDGED FIXES (CONFIRMED REMEDIATED)

**P0-02 — Confirmation tag verification:** Correctly fixed. `process_update` now computes `expected_tag = hmac.new(next_state.key_schedule.confirmation_key, transcript_hash, "sha256").digest()` and calls `hmac.compare_digest(expected_tag, update._confirmation_tag)` with a constant-time comparison. The tag is populated by `add_member` via `_conf_tag_sender` and carried in `GroupUpdate._confirmation_tag`. The guard is conditional on the tag being present (`if update._confirmation_tag is not None`), which is acceptable for backward compatibility with deserialized updates that lack the field.

**P1-01 — EncryptedGroupSecrets HPKE domain label:** Correctly fixed. Both `add_member` (seal) and `join` (open) now use `info=b"MLS 1.0 EncryptedGroupSecrets"`. The domain label is consistent across both sides.

**P0-03 (partial) — MQTT and WebRTC transports:** Both tests correctly migrated to `encrypt_application_message` / `decrypt_application_message` with inline comments referencing the finding (`# P0-03: use MLS-compliant encrypt_application_message`).

**PSK injection:** `_psk_secret()` now implements the RFC 9420 §8.4 multi-PSK XOR accumulation chain, replacing the `NotImplementedError` placeholder.

---

## PART V — COMPLIANCE MATRIX (UPDATED)

| RFC / Section | Requirement | Status | Notes |
|---|---|---|---|
| RFC 9180 §4.1 | KEM `eae_prk` / `shared_secret` labels | ✅ Compliant | |
| RFC 9180 §5.1 | KeySchedule salt/IKM order | ✅ Compliant | |
| RFC 9420 §8 | ExpandWithLabel VarInt encoding | ✅ Compliant | IETF crypto-basics vectors pass |
| RFC 9420 §8 | KeySchedule label strings | ✅ Compliant | |
| RFC 9420 §8 | GroupContext in epoch derivation | ❌ **P0-01** | `b""` unchanged |
| RFC 9420 §8.3 | Confirmation tag verification | ✅ **FIXED** | `hmac.compare_digest` used |
| RFC 9420 §8.4 | PSK injection chain | ✅ **FIXED** | Full multi-PSK XOR implemented |
| RFC 9420 §9 | E2E MQTT/WebRTC use SecretTree | ✅ **FIXED** | |
| RFC 9420 §9 | E2E WebSocket uses SecretTree | ❌ **P0-03 residual** | Raw AESGCM still present |
| RFC 9420 §12.4 | EncryptWithLabel for GroupSecrets | ✅ **FIXED** | `info=b"MLS 1.0 EncryptedGroupSecrets"` |
| RFC 9420 §7.2 | LeafNode TBS includes group binding | ⚠️ **P1-04** | `verify_signature()` ignores source |
| LBBT Math | Single canonical tree math module | ⚠️ **P1-03** | `tree_math.py` still dead |
| Codebase hygiene | No duplicate dead functions | ⚠️ **N-01** | `encode_varint` introduced but unused |

---

## CERTIFICATION DECISION

> **CERTIFICATION WITHHELD — P0-01 BLOCKING.**
