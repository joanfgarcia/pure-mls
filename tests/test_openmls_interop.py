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
# P8-3: Welcome TLS wire format validation
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
	"""
	Full round-trip: OpenMLS creates group → pure-mls joins and verifies epoch_authenticator.

	BLOCKED on P8-3: HPKE GroupSecrets decrypt requires EncryptWithLabel
	info parameter clarification (tested: empty, egi, MLS-1.0-Welcome+egi — all fail).
	"""
	pytest.skip("P8-3 HPKE GroupSecrets decrypt not yet resolved")


@pytest.mark.interop
@pytest.mark.skipif(
	not HAVE_OPENMLS,
	reason="openmls-cli not found",
)
def test_pure_mls_creates_openmls_joins() -> None:
	"""
	Full round-trip: pure-mls creates group → OpenMLS client joins.

	BLOCKED on P8-3 (Welcome wire format) and P8-4 (KeyPackage TLS).
	"""
	pytest.skip("P8-3/P8-4 not yet fully resolved")
