from dataclasses import dataclass, field
from typing import Optional


@dataclass
class KeyPackage:
	"""RFC 9420 §10.1: KeyPackage carries a member's identity + HPKE init key.

	The leaf_node_signature authenticates the init_key_pub with the identity key,
	proving the owner controls both keys (RFC 9420 §10.1).
	"""

	identity_key_pub: bytes  # Ed25519 Signature Public Key (32 bytes)
	init_key_pub: bytes  # X25519 HPKE Public Key (32 bytes)
	leaf_node_signature: bytes = b""  # Ed25519(KeyPackageTBS), set by create()

	_CIPHER_SUITE: int = 0x0001  # MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

	@classmethod
	def create(cls, identity_key_pub: bytes, init_key_pub: bytes, sign_fn) -> "KeyPackage":
		"""Factory: build and sign a KeyPackage (RFC 9420 §10.1).

		sign_fn(tbs_bytes) -> signature_bytes  (e.g. SignatureKey.sign)
		"""
		kp = cls(identity_key_pub=identity_key_pub, init_key_pub=init_key_pub, leaf_node_signature=b"")
		tbs = kp._tbs_bytes()
		kp.leaf_node_signature = sign_fn(tbs)
		return kp

	def _tbs_bytes(self) -> bytes:
		"""KeyPackageTBS = cipher_suite(u16) + init_key(opaque32) + identity_key(opaque32)."""
		return (
			self._CIPHER_SUITE.to_bytes(2, "big")
			+ len(self.init_key_pub).to_bytes(4, "big")
			+ self.init_key_pub
			+ len(self.identity_key_pub).to_bytes(4, "big")
			+ self.identity_key_pub
		)

	def verify_signature(self) -> None:
		"""Verify leaf_node_signature against identity_key_pub.

		Raises InvalidSignature if the signature is invalid or missing.
		"""
		from cryptography.exceptions import InvalidSignature  # noqa: F401
		from cryptography.hazmat.primitives.asymmetric import ed25519

		if not self.leaf_node_signature:
			raise ValueError("KeyPackage has no leaf_node_signature")
		pub = ed25519.Ed25519PublicKey.from_public_bytes(self.identity_key_pub)
		pub.verify(self.leaf_node_signature, self._tbs_bytes())

	def to_bytes(self) -> bytes:
		"""TLS wire format: identity_key(32) + init_key(32) + signature(64)."""
		return self.identity_key_pub + self.init_key_pub + self.leaf_node_signature

	@classmethod
	def from_bytes(cls, data: bytes) -> "KeyPackage":
		if len(data) == 64:
			# Legacy format (no signature) — for backward compat
			return cls(identity_key_pub=data[:32], init_key_pub=data[32:], leaf_node_signature=b"")
		if len(data) == 128:
			return cls(
				identity_key_pub=data[:32],
				init_key_pub=data[32:64],
				leaf_node_signature=data[64:128],
			)
		raise ValueError(f"Invalid KeyPackage size: {len(data)}")


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
		# After __post_init__ in EpochState, this list becomes a frozen tuple
		self.nodes: list[LeafNode | ParentNode | None] | tuple[LeafNode | ParentNode | None, ...] = (
			[None] * (2 * num_leaves - 1) if num_leaves > 0 else []
		)

	def freeze(self) -> None:
		"""Locks the tree structure to prevent mutated references from bypassing EpochState freezing."""
		if isinstance(self.nodes, list):
			self.nodes = tuple(self.nodes)

	def set_leaf(self, index: int, leaf: LeafNode) -> None:
		if index % 2 != 0:
			raise ValueError("Leaves must be inserted at even indices")
		if isinstance(self.nodes, tuple):
			raise TypeError("RatchetTree is frozen and immutable.")
		self.nodes[index] = leaf

	def set_parent(self, index: int, parent_node: ParentNode) -> None:
		if index % 2 == 0:
			raise ValueError("Parents must be inserted at odd indices")
		if isinstance(self.nodes, tuple):
			raise TypeError("RatchetTree is frozen and immutable.")
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
				kp_bytes = node.key_package.to_bytes()
				tree_serialized.extend(b"\x01" + len(kp_bytes).to_bytes(2, "big") + kp_bytes)
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
				# Length-prefixed KeyPackage (2-byte big-endian length header)
				kp_size = int.from_bytes(data[offset : offset + 2], "big")
				offset += 2
				kp = KeyPackage.from_bytes(data[offset : offset + kp_size])
				nodes.append(LeafNode(key_package=kp))
				offset += kp_size
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

	def level(self, index: int) -> int:
		"""RFC 9420 Appendix C: level(x) = number of trailing 1-bits of x.

		Leaves (even nodes) have level 0. Root has the highest level.
		"""
		if index & 0x01 == 0:
			return 0
		k = 0
		while (index >> k) & 0x01 == 1:
			k += 1
		return k

	def _root(self) -> int:
		"""RFC 9420 Appendix C.2: root index for a given tree."""
		n = self.num_leaves
		if n <= 1:
			return 0
		w = 2 * n - 1
		k = w.bit_length()
		return (1 << (k - 1)) - 1

	def _parent(self, x: int) -> int:
		"""RFC 9420 Appendix C.2: parent(x, W)."""
		n = self.num_leaves
		if n <= 1:
			return 0
		w = 2 * n - 1
		r = self._root()
		if x == r:
			return x

		k = self.level(x)
		b = (x >> (k + 1)) & 0x01
		p = x ^ ((0x01 << k) | (b << (k + 1)))

		# RFC 9420 bounds check logic directly in loop
		while p >= w:
			pk = self.level(p)
			pb = (p >> (pk + 1)) & 0x01
			p = p ^ ((0x01 << pk) | (pb << (pk + 1)))

		return p

	def _sibling(self, x: int) -> int:
		"""RFC 9420 Appendix C.2: sibling(x, W)."""
		n = self.num_leaves
		if n <= 1:
			return x
		p = self._parent(x)
		k = self.level(p)
		if x < p:
			# x is left child, return right child
			return p + (1 << (k - 1))
		else:
			# x is right child, return left child
			return p - (1 << (k - 1))

	def direct_path(self, leaf_index: int) -> list[int]:
		"""RFC 9420 §7.1: direct path from leaf_index to root (exclusive of leaf).

		Returns list of ancestor node indices from parent to root.
		"""
		root = self._root()
		x = leaf_index
		n = len(self.nodes)
		path: list[int] = []
		if x == root:
			return path
		while True:
			p = self._parent(x)
			if p >= n:
				break
			path.append(p)
			if p == root:
				break
			x = p
		return path

	def copath(self, leaf_index: int) -> list[int]:
		"""RFC 9420 §7.1.3: copath = siblings of the direct_path nodes.

		Returns list of sibling indices for each node in the direct path.
		If a sibling is out of bounds, it is represented as -1 to maintain the
		same array length as direct_path (RFC 9420 requirement).
		"""
		dpath = self.direct_path(leaf_index)
		n = len(self.nodes)
		copath = []
		x = leaf_index
		for p in dpath:
			sib = self._sibling(x)
			if sib < n:
				copath.append(sib)
			else:
				copath.append(-1)
			x = p
		return copath

	def resolution(self, index: int) -> list[int]:
		"""RFC 9420 §7.2: resolution(x) = non-blank subtree leaves.

		Returns list of leaf indices that can receive path secrets at node x.
		"""
		if index < 0 or index >= len(self.nodes):
			return []
		node = self.nodes[index]
		if index % 2 == 0:  # leaf
			return [index] if node is not None else []
		# Parent node: union of resolution of children
		lvl = self.level(index)
		left = index - (1 << (lvl - 1))
		right = index + (1 << (lvl - 1))
		result = []
		if self.nodes[index] is None:
			result.extend(self.resolution(left))
			result.extend(self.resolution(right))
		else:
			result.append(index)
		return result
