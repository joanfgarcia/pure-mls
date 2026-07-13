"""IETF tree-validation known-answer tests (suite 1 subset of tree-validation.json).

Ground-truth from mlswg/mls-implementations. Validates:
- resolution() against OpenMLS for every node (audit M5).
- tree_hash() for full (power-of-two) trees.

Known gap (xfail): pure-mls parses a truncated ratchet_tree (trailing blank nodes
omitted, per RFC 9420 §12.4.3.3) into a non-power-of-two tree, whereas MLS trees always
have a power-of-two leaf count. This makes tree_hash() diverge for such trees and is the
next focused fix (round the parsed tree up to the canonical power-of-two size).
"""

import json
import pathlib

import pytest

from pure_mls.tree import RatchetTree

_VECTORS = json.loads(pathlib.Path("tests/ietf_vectors/tree-validation-suite1.json").read_text())


def _entries():
	return _VECTORS


def test_resolution_matches_ietf() -> None:
	checked = 0
	for e in _entries():
		rt = RatchetTree.from_bytes(bytes.fromhex(e["tree"]))
		for i in range(len(rt.nodes)):
			assert rt.resolution(i) == e["resolutions"][i], f"resolution mismatch at node {i}"
			checked += 1
	assert checked > 0


def test_tree_hash_matches_ietf_for_full_trees() -> None:
	"""For trees whose wire form is already the full (power-of-two) tree, tree_hash matches."""
	checked = 0
	for e in _entries():
		rt = RatchetTree.from_bytes(bytes.fromhex(e["tree"]))
		if len(rt.nodes) != len(e["tree_hashes"]):
			continue  # truncated/non-power-of-two wire form — see the xfail below
		for i in range(len(rt.nodes)):
			assert rt._node_hash(i).hex() == e["tree_hashes"][i], f"tree_hash mismatch at node {i}"
			checked += 1
	assert checked > 0, "expected at least one full (power-of-two) tree in the vector"


@pytest.mark.xfail(
	reason="pure-mls parses a truncated ratchet_tree into a non-power-of-two tree; MLS trees "
	"are always power-of-two. tree_hash() diverges until _parse rounds up to the canonical size.",
	strict=True,
)
def test_tree_hash_matches_ietf_for_truncated_trees() -> None:
	e = next(x for x in _entries() if len(RatchetTree.from_bytes(bytes.fromhex(x["tree"])).nodes) != len(x["tree_hashes"]))
	rt = RatchetTree.from_bytes(bytes.fromhex(e["tree"]))
	# The vector indexes hashes over the full power-of-two tree; our parse is smaller.
	for i in range(len(e["tree_hashes"])):
		expected = e["tree_hashes"][i]
		got = rt._node_hash(i).hex() if i < len(rt.nodes) else None
		assert got == expected
