"""Tests for RFC 9420 §12 Proposal types (Phase 4)."""

import os

import pytest

from pure_mls.proposals import (
	AddProposal,
	ProposalOrRef,
	ProposalType,
	PSKProposal,
	RemoveProposal,
	UpdateProposal,
	proposal_from_bytes,
	proposal_ref,
)


class TestAddProposal:
	def test_roundtrip(self):
		kp = os.urandom(128)
		a = AddProposal(key_package_bytes=kp)
		data = a.to_bytes()
		a2, offset = AddProposal.from_bytes(data)
		assert a2.key_package_bytes == kp
		assert offset == len(data)

	def test_proposal_type(self):
		a = AddProposal(key_package_bytes=b"\x00" * 32)
		assert int.from_bytes(a.to_bytes()[:2], "big") == ProposalType.ADD


class TestUpdateProposal:
	def test_roundtrip(self):
		ln = os.urandom(64)
		u = UpdateProposal(leaf_node_bytes=ln)
		data = u.to_bytes()
		u2, _ = UpdateProposal.from_bytes(data)
		assert u2.leaf_node_bytes == ln

	def test_proposal_type(self):
		u = UpdateProposal(leaf_node_bytes=b"\x00" * 32)
		assert int.from_bytes(u.to_bytes()[:2], "big") == ProposalType.UPDATE


class TestRemoveProposal:
	def test_roundtrip(self):
		r = RemoveProposal(removed=7)
		data = r.to_bytes()
		r2, _ = RemoveProposal.from_bytes(data)
		assert r2.removed == 7

	def test_zero_index(self):
		r = RemoveProposal(removed=0)
		r2, _ = RemoveProposal.from_bytes(r.to_bytes())
		assert r2.removed == 0

	def test_proposal_type(self):
		r = RemoveProposal(removed=0)
		assert int.from_bytes(r.to_bytes()[:2], "big") == ProposalType.REMOVE


class TestPSKProposal:
	def test_roundtrip(self):
		psk = PSKProposal(psk_id=b"my-psk-identifier", psk_nonce=os.urandom(16))
		data = psk.to_bytes()
		psk2, _ = PSKProposal.from_bytes(data)
		assert psk2.psk_id == b"my-psk-identifier"
		assert psk2.psk_nonce == psk.psk_nonce

	def test_proposal_type(self):
		psk = PSKProposal(psk_id=b"k", psk_nonce=b"\x00" * 4)
		assert int.from_bytes(psk.to_bytes()[:2], "big") == ProposalType.PRE_SHARED_KEY


class TestProposalDispatch:
	def test_dispatch_add(self):
		a = AddProposal(key_package_bytes=b"\x01" * 32)
		p, _ = proposal_from_bytes(a.to_bytes())
		assert isinstance(p, AddProposal)

	def test_dispatch_remove(self):
		r = RemoveProposal(removed=5)
		p, _ = proposal_from_bytes(r.to_bytes())
		assert isinstance(p, RemoveProposal)
		assert p.removed == 5

	def test_dispatch_update(self):
		u = UpdateProposal(leaf_node_bytes=b"\x02" * 32)
		p, _ = proposal_from_bytes(u.to_bytes())
		assert isinstance(p, UpdateProposal)

	def test_dispatch_psk(self):
		psk = PSKProposal(psk_id=b"x", psk_nonce=b"\x00" * 4)
		p, _ = proposal_from_bytes(psk.to_bytes())
		assert isinstance(p, PSKProposal)

	def test_unknown_type(self):
		bad = b"\xff\xff" + b"\x00" * 4
		with pytest.raises(ValueError, match="Unknown ProposalType"):
			proposal_from_bytes(bad)


class TestProposalRef:
	def test_length(self):
		a = AddProposal(key_package_bytes=b"\x00" * 32)
		ref = proposal_ref(a.to_bytes())
		assert len(ref) == 32  # SHA-256

	def test_deterministic(self):
		a = AddProposal(key_package_bytes=b"\xab" * 32)
		assert proposal_ref(a.to_bytes()) == proposal_ref(a.to_bytes())


class TestProposalOrRef:
	def test_by_value_roundtrip(self):
		a = AddProposal(key_package_bytes=b"\x00" * 16).to_bytes()
		por = ProposalOrRef(value=a)
		por2, _ = ProposalOrRef.from_bytes(por.to_bytes())
		assert por2.value == a

	def test_by_reference_roundtrip(self):
		ref = os.urandom(32)
		por = ProposalOrRef(reference=ref)
		por2, _ = ProposalOrRef.from_bytes(por.to_bytes())
		assert por2.reference == ref

	def test_invalid_no_value_or_ref(self):
		por = ProposalOrRef()
		with pytest.raises(ValueError, match="must have value or reference"):
			por.to_bytes()
