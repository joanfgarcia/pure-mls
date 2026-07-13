"""Audit MEDIUM robustness block: M5 (resolution), M6 (secret_tree paths),
M7 (wire bounds-checks), M8 (secret redaction in repr)."""

import pytest

from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.secret_tree import SecretTree, _get_path
from pure_mls.tls import read_opaque16, read_opaque32, read_vec8, read_vector16, read_vector32
from pure_mls.tree import ParentNode, RatchetTree


# M5 -------------------------------------------------------------------------
def test_resolution_maps_unmerged_leaves_to_node_indices() -> None:
	tree = RatchetTree(num_leaves=4)  # leaves at nodes 0,2,4,6; internal 1,5; root 3
	tree.set_parent(5, ParentNode(public_key=b"\x02" * 32, parent_hash=b"", unmerged_leaves=[3]))
	res = tree.resolution(5)
	assert 6 in res  # leaf index 3 -> node index 6
	assert 3 not in res  # the raw leaf index must not leak into a node-index resolution


# M6 -------------------------------------------------------------------------
@pytest.mark.parametrize("n_leaves", [2, 3, 4, 5, 6, 7, 8])
def test_secret_tree_path_matches_tree_math(n_leaves: int) -> None:
	"""secret_tree._get_path must agree with the trusted RatchetTree direct_path,
	including non-power-of-two sizes (audit M6)."""
	oracle = RatchetTree(num_leaves=n_leaves)
	for leaf in range(n_leaves):
		assert len(_get_path(leaf, n_leaves)) == len(oracle.direct_path(2 * leaf)), f"path mismatch n={n_leaves} leaf={leaf}"


# M7 -------------------------------------------------------------------------
def test_read_opaque16_rejects_truncated() -> None:
	with pytest.raises(ValueError):
		read_opaque16((100).to_bytes(2, "big") + b"\x00", 0)


def test_read_opaque32_rejects_truncated() -> None:
	with pytest.raises(ValueError):
		read_opaque32((100).to_bytes(4, "big") + b"\x00", 0)


def test_read_vector16_rejects_truncated() -> None:
	with pytest.raises(ValueError):
		read_vector16((100).to_bytes(2, "big"), 0)


def test_read_vector32_rejects_truncated() -> None:
	with pytest.raises(ValueError):
		read_vector32((100).to_bytes(4, "big"), 0)


def test_read_vec8_rejects_truncated() -> None:
	with pytest.raises(ValueError):
		read_vec8(bytes([100]), 0)


# L4 -------------------------------------------------------------------------
def test_varint_rejects_8byte_form_and_oversize() -> None:
	"""RFC 9420 §2.1.2: the 0b11 (8-byte) prefix is invalid; max length is 2^30 - 1."""
	from pure_mls.tls import _varint_decode, tls_varint

	with pytest.raises(ValueError):
		_varint_decode(bytes([0xC0, 0, 0, 0, 0, 0, 0, 0]), 0)  # prefix 0b11
	with pytest.raises(ValueError):
		tls_varint(0x40000000)  # 2^30, one past the max
	# canonical values round-trip at the boundaries
	for v in (0x3F, 0x40, 0x3FFF, 0x4000, 0x3FFFFFFF):
		enc = tls_varint(v)
		got, off = _varint_decode(enc, 0)
		assert got == v and off == len(enc)


# M8 -------------------------------------------------------------------------
def test_secret_tree_repr_redacts_secret() -> None:
	st = SecretTree(encryption_secret=b"\x01" * 32, n_leaves=2)
	r = repr(st)
	assert "redacted" in r
	assert (b"\x01" * 32).hex() not in r


def test_keyschedule_and_epochstate_repr_redact_secrets() -> None:
	group = MLSGroup.create(b"g", SignatureKey(), KemKey())
	ks = group.state.key_schedule
	assert "redacted" in repr(ks)
	assert ks.joiner_secret.hex() not in repr(ks)
	# EpochState must not leak KeySchedule secrets transitively
	assert "redacted" in repr(group.state)
	assert ks.joiner_secret.hex() not in repr(group.state)
