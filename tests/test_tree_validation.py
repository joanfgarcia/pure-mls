"""IETF tree-validation known-answer tests (suite 1 subset of tree-validation.json).

Ground-truth from mlswg/mls-implementations. Validates, against OpenMLS output, that:
- resolution() matches for every node (audit M5), and
- tree_hash() matches for every node, including trees whose wire form omitted trailing
  blank nodes (parsed back up to the canonical power-of-two size — the pow2 tree fix).
"""

import json
import pathlib

from pure_mls.tree import RatchetTree

_VECTORS = json.loads(pathlib.Path("tests/ietf_vectors/tree-validation-suite1.json").read_text())


def test_resolution_matches_ietf() -> None:
	checked = 0
	for e in _VECTORS:
		rt = RatchetTree.from_bytes(bytes.fromhex(e["tree"]))
		assert len(rt.nodes) == len(e["resolutions"]), "parsed tree size must match the canonical vector size"
		for i in range(len(e["resolutions"])):
			assert rt.resolution(i) == e["resolutions"][i], f"resolution mismatch at node {i}"
			checked += 1
	assert checked > 0


def test_tree_hash_matches_ietf() -> None:
	checked = 0
	for e in _VECTORS:
		rt = RatchetTree.from_bytes(bytes.fromhex(e["tree"]))
		assert len(rt.nodes) == len(e["tree_hashes"]), "parsed tree size must match the canonical vector size"
		for i in range(len(e["tree_hashes"])):
			assert rt._node_hash(i).hex() == e["tree_hashes"][i], f"tree_hash mismatch at node {i}"
			checked += 1
	assert checked > 0
