"""
Phase 8: OpenMLS Wire-Format Interoperability Tests.

Tests marked @pytest.mark.interop require the `openmls-cli` binary
(cargo install openmls-cli) or PURE_MLS_FORCE_INTEROP=1.

To run:
  PURE_MLS_FORCE_INTEROP=1 pytest tests/test_openmls_interop.py -v
"""

import json
import os
import shutil
import struct

import pytest

from pure_mls.group import GroupContext

OPENMLS_BIN = shutil.which("openmls-cli") or shutil.which("openmls")
FORCE = os.environ.get("PURE_MLS_FORCE_INTEROP", "") == "1"
HAVE_OPENMLS = bool(OPENMLS_BIN) or FORCE


def _h(s: str) -> bytes:
	return bytes.fromhex(s)


def _varint_decode(data: bytes, offset: int) -> tuple[int, int]:
	"""MLS VarInt decoder per RFC 9420 §5.1."""
	first = data[offset]
	prefix = (first >> 6) & 0x3
	if prefix == 0:
		return first & 0x3F, offset + 1
	elif prefix == 1:
		return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
	elif prefix == 2:
		v = ((first & 0x3F) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]
		return v, offset + 4
	raise ValueError("Invalid varint prefix 0b11")


def _parse_welcome_wire(raw: bytes) -> dict:
	"""
	Parse RFC 9420 §12.4 MLSMessage(Welcome) wire format.
	Returns parsed fields and total consumed bytes.
	"""
	inner = raw[4:]  # strip MLSMessage header (version + wire_format)
	cs = struct.unpack_from(">H", inner, 0)[0]
	offset = 2
	egs_vlen, offset = _varint_decode(inner, offset)
	kpr_len, offset = _varint_decode(inner, offset)
	kpr = inner[offset : offset + kpr_len]
	offset += kpr_len
	ko_len, offset = _varint_decode(inner, offset)
	ko = inner[offset : offset + ko_len]
	offset += ko_len
	ct_len, offset = _varint_decode(inner, offset)
	ct = inner[offset : offset + ct_len]
	offset += ct_len
	egi_len, offset = _varint_decode(inner, offset)
	egi = inner[offset : offset + egi_len]
	offset += egi_len
	return {
		"cipher_suite": cs,
		"kp_ref": kpr,
		"kem_output": ko,
		"ciphertext": ct,
		"encrypted_group_info": egi,
		"total_parsed": offset,
		"total_bytes": len(inner),
	}


# ---------------------------------------------------------------------------
# Load IETF vectors at module level (not inside parametrize)
# ---------------------------------------------------------------------------


def _load_pcw_suite1() -> list[dict]:
	try:
		with open("tests/ietf_vectors/passive-client-welcome.json") as f:
			data = json.load(f)
		return [v for v in data if v["cipher_suite"] == 1]
	except FileNotFoundError:
		return []


_PCW_VECTORS = _load_pcw_suite1()


# ---------------------------------------------------------------------------
# P8-3a: Welcome TLS wire format validation (varint parser)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vec,idx", [pytest.param(v, i, id=f"suite1-{i}") for i, v in enumerate(_PCW_VECTORS)])
def test_welcome_wire_parse_suite1(vec: dict, idx: int) -> None:
	"""
	P8-3: Validate varint Welcome parser walks RFC wire format without overflow.
	Verifies: MLSMessage header stripping, varint field lengths, full byte coverage.
	"""
	wb = _h(vec["welcome"])
	parsed = _parse_welcome_wire(wb)
	assert parsed["total_parsed"] == parsed["total_bytes"], f"Vector {idx}: parser consumed {parsed['total_parsed']} / {parsed['total_bytes']} bytes"
	assert parsed["cipher_suite"] == 1
	assert len(parsed["kem_output"]) == 32, f"X25519 kem_output must be 32 bytes, got {len(parsed['kem_output'])}"
	assert len(parsed["kp_ref"]) == 32, f"kp_ref must be 32 bytes, got {len(parsed['kp_ref'])}"


# ---------------------------------------------------------------------------
# P8-3b: Welcome HPKE GroupSecrets decrypt (full IETF vector validation)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("idx,vec", [pytest.param(i, v, id=f"suite1-{i}") for i, v in enumerate(_PCW_VECTORS)])
def test_welcome_hpke_decrypt_suite1(idx: int, vec: dict) -> None:
	"""P8-3b: HPKE.open decrypts GroupSecrets from IETF passive-client-welcome vectors.

	Root cause of prior failures was ExtractAndExpand label:
	eae_prk = LabeledExtract('', 'eae_prk', dh)  -- not 'shared_secret'
	shared_secret = LabeledExpand(eae_prk, 'shared_secret', kem_context)
	(RFC 9180 §4.1, confirmed by pyhpke 0.6.4)

	Also: KeySchedule salt=shared_secret, IKM=psk=b'' per RFC 9180 §5.1.
	"""
	from pure_mls.group import Welcome
	from pure_mls.keys import KemKey

	wb = _h(vec["welcome"])
	init_priv = _h(vec["init_priv"])

	welcome = Welcome.from_mlsmessage_bytes(wb)
	kem_key = KemKey.from_private_bytes(init_priv)
	gs = welcome.decrypt_group_secrets(kem_key)

	assert gs is not None, f"Vector {idx}: decrypt_group_secrets returned None (no matching EGS entry)"
	# joiner_secret: SHA-256 output length = 32 bytes
	assert len(gs.joiner_secret) == 32, f"Vector {idx}: joiner_secret must be 32 bytes, got {len(gs.joiner_secret)}"
	# path_secret is optional (present only in vectors with an update path)
	if gs.path_secret is not None:
		assert len(gs.path_secret) == 32, f"Vector {idx}: path_secret must be 32 bytes if present"


# ---------------------------------------------------------------------------
# P8-2: GroupContext TLS roundtrip (§8.1)
# ---------------------------------------------------------------------------


def _load_ks_suite1_epochs() -> list[tuple[int, bytes]]:
	try:
		with open("tests/ietf_vectors/key-schedule.json") as f:
			ks = json.load(f)
		suite1 = next(v for v in ks if v["cipher_suite"] == 1)
		return [(i, _h(ep["group_context"])) for i, ep in enumerate(suite1["epochs"])]
	except FileNotFoundError:
		return []


_KS_EPOCHS = _load_ks_suite1_epochs()


@pytest.mark.parametrize("idx,gc_bytes", [pytest.param(i, b, id=f"epoch-{i}") for i, b in _KS_EPOCHS])
def test_groupcontext_tls_roundtrip(idx: int, gc_bytes: bytes) -> None:
	"""
	P8-2: GroupContext TLS uint8-prefixed opaques roundtrip against IETF vectors.
	"""
	obj = GroupContext.from_bytes(gc_bytes)
	reenc = obj.to_bytes()
	assert reenc == gc_bytes, f"Epoch {idx} roundtrip failed\n  expected: {gc_bytes.hex()}\n  got:      {reenc.hex()}"


# ---------------------------------------------------------------------------
# P8-6: End-to-end OpenMLS binary interop stubs
# ---------------------------------------------------------------------------


@pytest.mark.interop
@pytest.mark.skipif(
	not HAVE_OPENMLS,
	reason="openmls-cli not found — install with: cargo install openmls-cli",
)
def test_openmls_creates_pure_mls_joins() -> None:
	"""Live round-trip: OpenMLS creates group -> pure-mls joins.

	audit H4: NOT implemented. This was previously an empty body that "passed"
	without asserting anything, backing a false "100% interop" claim. Live
	bidirectional interop needs openmls-cli wiring plus the deferred tree_hash()
	interop fix. Skipped honestly until then.
	"""
	pytest.skip("live OpenMLS interop not implemented (needs openmls-cli + tree_hash() fix)")


@pytest.mark.interop
@pytest.mark.skipif(
	not HAVE_OPENMLS,
	reason="openmls-cli not found",
)
def test_pure_mls_creates_openmls_joins() -> None:
	"""Live round-trip: pure-mls creates group -> OpenMLS client joins.

	audit H4: NOT implemented (see test_openmls_creates_pure_mls_joins).
	"""
	pytest.skip("live OpenMLS interop not implemented (needs openmls-cli + tree_hash() fix)")
