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

from pure_mls.tls import (
	read_opaque,
	read_u16,
	read_u32,
	tls_u16,
	tls_u32,
	tls_varint,
)


class ProposalType(IntEnum):
	"""RFC 9420 §12.1: ProposalType enum values (uint16)."""

	ADD = 0x0001
	UPDATE = 0x0002
	REMOVE = 0x0003
	PRE_SHARED_KEY = 0x0004
	REINIT = 0x0005
	EXTERNAL_INIT = 0x0007
	GROUP_CONTEXT_EXTENSIONS = 0x000A


def _opaque_varint(data: bytes) -> bytes:
	"""Encode bytes as varint-prefixed opaque<V> per RFC 9420 §5.1."""
	return tls_varint(len(data)) + data


@dataclass
class AddProposal:
	"""RFC 9420 §12.1.1: Add a new member via their KeyPackage."""

	key_package_bytes: bytes  # TLS-encoded KeyPackage

	def to_bytes(self) -> bytes:
		return tls_u16(ProposalType.ADD) + _opaque_varint(self.key_package_bytes)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["AddProposal", int]:
		proposal_type, offset = read_u16(data, offset)
		if proposal_type != ProposalType.ADD:
			raise ValueError(f"Expected ADD, got {proposal_type:#06x}")
		kp_bytes, offset = read_opaque(data, offset)
		return cls(key_package_bytes=kp_bytes), offset


@dataclass
class UpdateProposal:
	"""RFC 9420 §12.1.2: Refresh the sender's leaf key material."""

	leaf_node_bytes: bytes  # TLS-encoded LeafNode

	def to_bytes(self) -> bytes:
		return tls_u16(ProposalType.UPDATE) + _opaque_varint(self.leaf_node_bytes)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["UpdateProposal", int]:
		proposal_type, offset = read_u16(data, offset)
		if proposal_type != ProposalType.UPDATE:
			raise ValueError(f"Expected UPDATE, got {proposal_type:#06x}")
		ln_bytes, offset = read_opaque(data, offset)
		return cls(leaf_node_bytes=ln_bytes), offset


@dataclass
class RemoveProposal:
	"""RFC 9420 §12.1.3: Evict a member by their leaf index."""

	removed: int  # leaf index (uint32)

	def to_bytes(self) -> bytes:
		return tls_u16(ProposalType.REMOVE) + tls_u32(self.removed)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["RemoveProposal", int]:
		proposal_type, offset = read_u16(data, offset)
		if proposal_type != ProposalType.REMOVE:
			raise ValueError(f"Expected REMOVE, got {proposal_type:#06x}")
		removed, offset = read_u32(data, offset)
		return cls(removed=removed), offset


@dataclass
class PSKProposal:
	"""RFC 9420 §12.1.4: Inject a PreSharedKey into the next epoch.

	PSK ID wire format (simplified — external PSK only):
		psk_type (1B: 0x01=external) | psk_id<V>(opaque_varint) | psk_nonce<V>(opaque)
	"""

	psk_id: bytes  # application-defined PSK identifier
	psk_nonce: bytes  # fresh random nonce (prevents replay)

	def to_bytes(self) -> bytes:
		psk_id_wire = (
			b"\x01"  # psk_type = external
			+ _opaque_varint(self.psk_id)
			+ _opaque_varint(self.psk_nonce)
		)
		return tls_u16(ProposalType.PRE_SHARED_KEY) + _opaque_varint(psk_id_wire)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["PSKProposal", int]:
		proposal_type, offset = read_u16(data, offset)
		if proposal_type != ProposalType.PRE_SHARED_KEY:
			raise ValueError(f"Expected PSK, got {proposal_type:#06x}")
		psk_id_wire, offset = read_opaque(data, offset)
		inner = 0
		_psk_type = psk_id_wire[inner]
		inner += 1
		psk_id, inner = read_opaque(psk_id_wire, inner)
		psk_nonce, inner = read_opaque(psk_id_wire, inner)
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
			return b"\x01" + tls_varint(len(self.value)) + self.value
		elif self.reference is not None:
			return b"\x02" + tls_varint(len(self.reference)) + self.reference
		raise ValueError("ProposalOrRef must have value or reference")

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["ProposalOrRef", int]:
		kind = data[offset]
		offset += 1
		if kind == 0x01:
			value, offset = read_opaque(data, offset)
			return cls(value=value), offset
		elif kind == 0x02:
			reference, offset = read_opaque(data, offset)
			return cls(reference=reference), offset
		raise ValueError(f"Unknown ProposalOrRef kind: {kind:#04x}")


@dataclass
class Commit:
	"""RFC 9420 §12.1: Commit message body.

	Wire format: proposals<V> + optional<UpdatePath>
	"""

	proposals: list[ProposalOrRef]
	# UpdatePath is handled in group.py to avoid circular dependencies
	update_path_bytes: bytes | None = None

	def to_bytes(self) -> bytes:
		prop_bytes = b"".join(p.to_bytes() for p in self.proposals)
		res = tls_varint(len(prop_bytes)) + prop_bytes
		if self.update_path_bytes is not None:
			res += b"\x01" + tls_varint(len(self.update_path_bytes)) + self.update_path_bytes
		else:
			res += b"\x00"
		return res

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["Commit", int]:
		# proposals<V> handled by read_opaque (VarInt prefix per RFC 9420)
		props_data, offset = read_opaque(data, offset)
		props = []
		p_offset = 0
		while p_offset < len(props_data):
			p, p_offset = ProposalOrRef.from_bytes(props_data, p_offset)
			props.append(p)

		has_path = data[offset]
		offset += 1
		path_bytes = None
		if has_path:
			path_bytes, offset = read_opaque(data, offset)

		return cls(proposals=props, update_path_bytes=path_bytes), offset
