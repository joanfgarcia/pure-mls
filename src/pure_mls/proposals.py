"""RFC 9420 §12: Proposal types and wire formats.

Proposal = one of:
  Add         (§12.1.1) – introduces a new member via KeyPackage
  Remove      (§12.1.3) – evicts a member by leaf index
  Update      (§12.1.2) – refreshes the sender's leaf key material
  PreSharedKey (§12.1.4) – injects a PSK into the next epoch
  ReInit      (§12.1.5) – requests a group reset (tombstone)

Each Proposal serialises as:
  proposal_type (uint16 ProposalType) | body...

ProposalRef = Hash(Proposal wire bytes) — used by Commit.proposals[].
A Commit embeds a vector of ProposalOrRef items, each prefixed by a
type byte (0x01=by_value, 0x02=by_reference).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum


class ProposalType(IntEnum):
	"""RFC 9420 §12.1: ProposalType enum values (uint16)."""

	ADD = 0x0001
	UPDATE = 0x0002
	REMOVE = 0x0003
	PRE_SHARED_KEY = 0x0004
	REINIT = 0x0005
	EXTERNAL_INIT = 0x0007
	GROUP_CONTEXT_EXTENSIONS = 0x000A


def _u16(n: int) -> bytes:
	return n.to_bytes(2, "big")


def _u32(n: int) -> bytes:
	return n.to_bytes(4, "big")


def _opaque(data: bytes) -> bytes:
	return len(data).to_bytes(4, "big") + data


def _read_u16(data: bytes, offset: int) -> tuple[int, int]:
	return int.from_bytes(data[offset : offset + 2], "big"), offset + 2


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
	return int.from_bytes(data[offset : offset + 4], "big"), offset + 4


def _read_opaque(data: bytes, offset: int) -> tuple[bytes, int]:
	length = int.from_bytes(data[offset : offset + 4], "big")
	offset += 4
	return data[offset : offset + length], offset + length


@dataclass
class AddProposal:
	"""RFC 9420 §12.1.1: Add a new member via their KeyPackage."""

	key_package_bytes: bytes  # TLS-encoded KeyPackage

	def to_bytes(self) -> bytes:
		return _u16(ProposalType.ADD) + _opaque(self.key_package_bytes)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["AddProposal", int]:
		proposal_type, offset = _read_u16(data, offset)
		assert proposal_type == ProposalType.ADD, f"Expected ADD, got {proposal_type:#06x}"
		kp_bytes, offset = _read_opaque(data, offset)
		return cls(key_package_bytes=kp_bytes), offset


@dataclass
class UpdateProposal:
	"""RFC 9420 §12.1.2: Refresh the sender's leaf key material."""

	leaf_node_bytes: bytes  # TLS-encoded LeafNode

	def to_bytes(self) -> bytes:
		return _u16(ProposalType.UPDATE) + _opaque(self.leaf_node_bytes)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["UpdateProposal", int]:
		proposal_type, offset = _read_u16(data, offset)
		assert proposal_type == ProposalType.UPDATE, f"Expected UPDATE, got {proposal_type:#06x}"
		ln_bytes, offset = _read_opaque(data, offset)
		return cls(leaf_node_bytes=ln_bytes), offset


@dataclass
class RemoveProposal:
	"""RFC 9420 §12.1.3: Evict a member by their leaf index."""

	removed: int  # leaf index (uint32)

	def to_bytes(self) -> bytes:
		return _u16(ProposalType.REMOVE) + _u32(self.removed)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["RemoveProposal", int]:
		proposal_type, offset = _read_u16(data, offset)
		assert proposal_type == ProposalType.REMOVE, f"Expected REMOVE, got {proposal_type:#06x}"
		removed, offset = _read_u32(data, offset)
		return cls(removed=removed), offset


@dataclass
class PSKProposal:
	"""RFC 9420 §12.1.4: Inject a PreSharedKey into the next epoch.

	PSK ID wire format (simplified — external PSK only):
		psk_type (1B: 0x01=external) | psk_id<V>(opaque32) | psk_nonce<V>(opaque)
	"""

	psk_id: bytes  # application-defined PSK identifier
	psk_nonce: bytes  # fresh random nonce (prevents replay)

	def to_bytes(self) -> bytes:
		psk_id_wire = (
			b"\x01"  # psk_type = external
			+ _opaque(self.psk_id)
			+ len(self.psk_nonce).to_bytes(1, "big")
			+ self.psk_nonce
		)
		return _u16(ProposalType.PRE_SHARED_KEY) + _opaque(psk_id_wire)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["PSKProposal", int]:
		proposal_type, offset = _read_u16(data, offset)
		assert proposal_type == ProposalType.PRE_SHARED_KEY, f"Expected PSK, got {proposal_type:#06x}"
		psk_id_wire, offset = _read_opaque(data, offset)
		inner = 0
		_psk_type = psk_id_wire[inner]
		inner += 1
		psk_id, inner = _read_opaque(psk_id_wire, inner)
		nonce_len = psk_id_wire[inner]
		inner += 1
		psk_nonce = psk_id_wire[inner : inner + nonce_len]
		return cls(psk_id=psk_id, psk_nonce=psk_nonce), offset


# Union type alias
Proposal = AddProposal | UpdateProposal | RemoveProposal | PSKProposal


def proposal_from_bytes(data: bytes, offset: int = 0) -> tuple[Proposal, int]:
	"""Parse a Proposal from wire bytes (type dispatch on the uint16 ProposalType)."""
	proposal_type = int.from_bytes(data[offset : offset + 2], "big")
	if proposal_type == ProposalType.ADD:
		return AddProposal.from_bytes(data, offset)
	elif proposal_type == ProposalType.UPDATE:
		return UpdateProposal.from_bytes(data, offset)
	elif proposal_type == ProposalType.REMOVE:
		return RemoveProposal.from_bytes(data, offset)
	elif proposal_type == ProposalType.PRE_SHARED_KEY:
		return PSKProposal.from_bytes(data, offset)
	else:
		raise ValueError(f"Unknown ProposalType: {proposal_type:#06x}")


def proposal_ref(proposal_bytes: bytes) -> bytes:
	"""RFC 9420 §12.1: ProposalRef = SHA-256(proposal wire bytes).

	Used in Commit.proposals to reference a cached Proposal by hash rather than embedding it.
	"""
	return hashlib.sha256(proposal_bytes).digest()


@dataclass
class ProposalOrRef:
	"""RFC 9420 §12.2: Commit references proposals by value (0x01) or by hash reference (0x02)."""

	value: bytes | None = None  # if by_value: the full Proposal.to_bytes()
	reference: bytes | None = None  # if by_reference: the ProposalRef hash (32B)

	def to_bytes(self) -> bytes:
		if self.value is not None:
			return b"\x01" + _opaque(self.value)
		elif self.reference is not None:
			return b"\x02" + self.reference  # 32B, fixed-length (SHA-256 output)
		raise ValueError("ProposalOrRef must have value or reference")

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["ProposalOrRef", int]:
		kind = data[offset]
		offset += 1
		if kind == 0x01:
			value, offset = _read_opaque(data, offset)
			return cls(value=value), offset
		elif kind == 0x02:
			reference = data[offset : offset + 32]
			return cls(reference=reference), offset + 32
		raise ValueError(f"Unknown ProposalOrRef kind: {kind:#04x}")
