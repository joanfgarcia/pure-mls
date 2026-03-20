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

	def to_bytes(self) -> bytes:
		"""Version 2: Length-prefixed serialization with explicit node indices to prevent misalignment DOS (DeepSeek P0)."""
		tree_serialized = bytearray()
		for idx, node in enumerate(self.nodes):
			tree_serialized.extend(idx.to_bytes(4, "big"))
			if node is None:
				tree_serialized.extend(b"\x00")
			elif isinstance(node, LeafNode):
				tree_serialized.extend(b"\x01" + node.key_package.to_bytes())
			elif isinstance(node, ParentNode):
				tree_serialized.extend(b"\x02" + node.public_key + getattr(node, "parent_hash", b"\x00" * 32))
		return bytes(tree_serialized)

	@classmethod
	def from_bytes(cls, data: bytes) -> "RatchetTree":
		nodes: list[Optional[LeafNode | ParentNode]] = []
		offset = 0
		while offset < len(data):
			idx = int.from_bytes(data[offset : offset + 4], "big")
			offset += 4

			# Pad with None if there are gaps
			while len(nodes) < idx:
				nodes.append(None)

			node_type = data[offset : offset + 1]
			offset += 1

			if node_type == b"\x00":
				nodes.append(None)
			elif node_type == b"\x01":
				kp = KeyPackage.from_bytes(data[offset : offset + 64])
				nodes.append(LeafNode(key_package=kp))
				offset += 64
			elif node_type == b"\x02":
				pk = data[offset : offset + 32]
				ph = data[offset + 32 : offset + 64]
				nodes.append(ParentNode(public_key=pk, parent_hash=ph))
				offset += 64
			else:
				raise ValueError("Invalid node type")

		# Ensure correct RatchetTree size computation based on leaves
		num_leaves = (len(nodes) + 1) // 2
		tree = cls(num_leaves)
		tree.nodes = nodes
		return tree
