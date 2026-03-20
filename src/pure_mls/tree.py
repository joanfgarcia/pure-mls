from dataclasses import dataclass, field
from typing import Optional


@dataclass
class KeyPackage:
	"""
	The public identity and routing payload for an Agent.
	Equivalent to the MLS 'KeyPackage' struct.
	"""

	identity_key_pub: bytes  # Ed25519 Signature Public Key
	init_key_pub: bytes  # X25519 HPKE Public Key

	def to_bytes(self) -> bytes:
		"""Safe binary serialization (64 bytes total). Avoids Pickle RCE."""
		return self.identity_key_pub + self.init_key_pub

	@classmethod
	def from_bytes(cls, data: bytes) -> "KeyPackage":
		if len(data) != 64:
			raise ValueError("Invalid KeyPackage size")
		return cls(identity_key_pub=data[:32], init_key_pub=data[32:])


@dataclass
class LeafNode:
	"""
	Represents an active Agent (a leaf) in the binary tree.
	"""

	key_package: KeyPackage

	@property
	def public_key(self) -> bytes:
		"""The encryption key used by parent nodes to target this leaf."""
		return self.key_package.init_key_pub


@dataclass
class ParentNode:
	"""
	Represents an intermediate routing node in the binary tree.
	"""

	public_key: bytes  # X25519 HPKE Public Key
	parent_hash: bytes
	unmerged_leaves: list[int] = field(default_factory=list)


class RatchetTree:
	"""
	Representation of the mathematical MLS Tree state.
	Uses the LBBT array layout: Leaves at even indices, Parents at odd indices.
	"""

	def __init__(self, num_leaves: int) -> None:
		self.num_leaves = num_leaves
		# The array size is always 2*num_leaves - 1
		# Initialize all nodes as empty (None)
		self.nodes: list[Optional[LeafNode | ParentNode]] = [None] * (2 * num_leaves - 1) if num_leaves > 0 else []

	def set_leaf(self, index: int, leaf: LeafNode) -> None:
		if index % 2 != 0:
			raise ValueError("Leaves must be inserted at even indices")
		self.nodes[index] = leaf

	def set_parent(self, index: int, parent_node: ParentNode) -> None:
		if index % 2 == 0:
			raise ValueError("Parents must be inserted at odd indices")
		self.nodes[index] = parent_node

	def get_node(self, index: int) -> Optional[LeafNode | ParentNode]:
		if index < 0 or index >= len(self.nodes):
			return None
		return self.nodes[index]
