"""RFC 9420 Tree structures: Credential, Capabilities, LeafNode, KeyPackage, RatchetTree.

All to_bytes() / from_bytes() methods produce RFC 9420 wire format, compatible
with OpenMLS (Rust), mlspp (C++), and any other RFC-conforming implementation.

§7.2   LeafNode
§10.1  KeyPackage
§7.4   RatchetTree optional<Node> encoding
"""

import copy
import hashlib
from dataclasses import dataclass, field, replace
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from pure_mls.extensions import Capabilities
from pure_mls.tls import (
	read_extensions,
	read_opaque,
	read_u8,
	read_u16,
	read_u64,
	tls_extensions,
	tls_opaque,
	tls_u8,
	tls_u16,
	tls_u32,
	tls_u64,
	tls_varint,
)

# §7.2 Credential

CREDENTIAL_TYPE_BASIC = 0x0001


@dataclass
class Credential:
	"""RFC 9420 §7.2: Credential binds an identity to a leaf.

	credential_type=0x0001 (basic): identity is an opaque byte string.
	"""

	identity: bytes  # arbitrary identity bytes (e.g. agent name / DID)
	credential_type: int = CREDENTIAL_TYPE_BASIC

	def to_bytes(self) -> bytes:
		"""TLS encoding: credential_type(u16) + identity<V>."""
		return tls_u16(self.credential_type) + tls_opaque(self.identity)

	@classmethod
	def from_bytes(cls, data: bytes) -> "Credential":
		"""Parse from standalone bytes buffer (backward-compatible)."""
		obj, _ = cls.from_bytes_at(data, 0)
		return obj

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["Credential", int]:
		ctype, offset = read_u16(data, offset)
		identity, offset = read_opaque(data, offset)
		return cls(identity=identity, credential_type=ctype), offset

	@classmethod
	def basic(cls, identity: bytes) -> "Credential":
		return cls(identity=identity)


# §7.2 LeafNodeSource

LEAF_NODE_SOURCE_KEY_PACKAGE = 0x01
LEAF_NODE_SOURCE_UPDATE = 0x02
LEAF_NODE_SOURCE_COMMIT = 0x03

LEAF_NODE_SOURCE_KEY_PACKAGE = 0x01
LEAF_NODE_SOURCE_UPDATE = 0x02
LEAF_NODE_SOURCE_COMMIT = 0x03


# §7.2 LeafNode

_CIPHER_SUITE = 0x0001  # MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519


@dataclass
class LeafNode:
	"""RFC 9420 §7.2: LeafNode — the full leaf entry in the ratchet tree.

	encryption_key: X25519 HPKE public key (the init key for the leaf)
	signature_key:  Ed25519 public key (the identity signing key)
	credential:     Credential binding the identity to this leaf
	capabilities:   Capabilities declared by this leaf
	leaf_node_source: 0x01=key_package | 0x02=update | 0x03=commit
	signature:      Ed25519 signature over LeafNodeTBS
	"""

	encryption_key: bytes  # X25519 pub key, 32 bytes
	signature_key: bytes  # Ed25519 pub key, 32 bytes
	credential: Credential
	capabilities: Capabilities
	leaf_node_source: int = LEAF_NODE_SOURCE_KEY_PACKAGE
	lifetime: Optional[tuple[int, int]] = None  # (not_before, not_after) if source == key_package
	parent_hash: Optional[bytes] = None  # if source == commit
	extensions: list[tuple[int, bytes]] = field(default_factory=list)  # vec<Extension>
	signature: bytes = b""  # Ed25519(LeafNodeTBS), set by sign()

	@property
	def public_key(self) -> bytes:
		"""Alias for the encryption key (used by parent node HPKE targeting)."""
		return self.encryption_key

	@property
	def key_package(self) -> "KeyPackage":
		"""Compatibility shim: return a KeyPackage view of this LeafNode.

		Used by legacy code that accesses leaf.key_package.to_bytes() for hashing.
		"""
		return KeyPackage(
			leaf_node=self,
			init_key_pub=self.encryption_key,
			leaf_node_signature=self.signature,
		)

	def _tbs_bytes(self, group_id: bytes = b"", leaf_index: int = 0) -> bytes:
		"""LeafNodeTBS per RFC 9420 §7.2."""
		tbs = (
			tls_u16(_CIPHER_SUITE)
			+ tls_opaque(self.encryption_key)
			+ tls_opaque(self.signature_key)
			+ self.credential.to_bytes()
			+ self.capabilities.marshal()
			+ tls_u8(self.leaf_node_source)
		)

		# RFC 9420 §7.2: select block
		if self.leaf_node_source == LEAF_NODE_SOURCE_KEY_PACKAGE:
			if self.lifetime:
				tbs += tls_u64(self.lifetime[0]) + tls_u64(self.lifetime[1])
			else:
				# Default to zeros if missing (though should be present for KP)
				tbs += tls_u64(0) + tls_u64(0)
		elif self.leaf_node_source == LEAF_NODE_SOURCE_COMMIT:
			tbs += tls_opaque(self.parent_hash or b"")

		tbs += tls_extensions(self.extensions)

		if self.leaf_node_source in (LEAF_NODE_SOURCE_UPDATE, LEAF_NODE_SOURCE_COMMIT):
			tbs += tls_opaque(group_id) + tls_u32(leaf_index)
		return tbs

	def sign(self, sign_fn: Callable[[bytes], bytes], group_id: bytes = b"", leaf_index: int = 0) -> "LeafNode":
		"""Return a signed copy of this LeafNode."""

		tbs = self._tbs_bytes(group_id, leaf_index)
		return replace(self, signature=sign_fn(tbs))

	def verify_signature(self, group_id: bytes = b"", leaf_index: int = 0) -> None:
		"""Verify the Ed25519 signature on this LeafNode."""

		if not self.signature:
			raise ValueError("LeafNode has no signature")
		pub = ed25519.Ed25519PublicKey.from_public_bytes(self.signature_key)
		tbs = self._tbs_bytes(group_id=group_id, leaf_index=leaf_index)
		pub.verify(self.signature, tbs)

	def to_bytes(self) -> bytes:
		"""Serializes as LeafNode (RFC 9420 §7.2)."""
		bytes_ = (
			tls_opaque(self.encryption_key)
			+ tls_opaque(self.signature_key)
			+ self.credential.to_bytes()
			+ self.capabilities.marshal()
			+ tls_u8(self.leaf_node_source)
		)

		# RFC 9420 §7.2: select block
		if self.leaf_node_source == LEAF_NODE_SOURCE_KEY_PACKAGE:
			if self.lifetime:
				bytes_ += tls_u64(self.lifetime[0]) + tls_u64(self.lifetime[1])
			else:
				bytes_ += tls_u64(0) + tls_u64(0)
		elif self.leaf_node_source == LEAF_NODE_SOURCE_COMMIT:
			bytes_ += tls_opaque(self.parent_hash or b"")

		return bytes_ + tls_extensions(self.extensions) + tls_opaque(self.signature)

	@classmethod
	def from_bytes(cls, data: bytes) -> "LeafNode":
		"""Parse from standalone bytes buffer."""
		obj, _ = cls.from_bytes_at(data, 0)
		return obj

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["LeafNode", int]:
		# encryption_key: HPKEPublicKey (opaque<V>)
		encryption_key, offset = read_opaque(data, offset)
		# signature_key: SignaturePublicKey (opaque<V>)
		signature_key, offset = read_opaque(data, offset)

		credential, offset = Credential.from_bytes_at(data, offset)
		capabilities, offset = Capabilities.from_bytes_at(data, offset)
		leaf_node_source, offset = read_u8(data, offset)

		# RFC 9420 §7.2: select block
		lifetime = None
		parent_hash = None
		if leaf_node_source == LEAF_NODE_SOURCE_KEY_PACKAGE:
			nb, offset = read_u64(data, offset)
			na, offset = read_u64(data, offset)
			lifetime = (nb, na)
		elif leaf_node_source == LEAF_NODE_SOURCE_COMMIT:
			parent_hash, offset = read_opaque(data, offset)

		extensions, offset = read_extensions(data, offset)
		signature, offset = read_opaque(data, offset)

		return cls(
			encryption_key=encryption_key,
			signature_key=signature_key,
			credential=credential,
			capabilities=capabilities,
			leaf_node_source=leaf_node_source,
			lifetime=lifetime,
			parent_hash=parent_hash,
			extensions=extensions,
			signature=signature,
		), offset

	@classmethod
	def create(cls, encryption_key: bytes, signature_key: bytes, identity: bytes, sign_fn: Callable[[bytes], bytes]) -> "LeafNode":
		"""Factory: create and sign a LeafNode for a new member."""
		node = cls(
			encryption_key=encryption_key,
			signature_key=signature_key,
			credential=Credential.basic(identity),
			capabilities=Capabilities.default(),
			leaf_node_source=LEAF_NODE_SOURCE_KEY_PACKAGE,
		)
		return node.sign(sign_fn)


# §10.1 KeyPackage


@dataclass
class KeyPackage:
	"""RFC 9420 §10.1: KeyPackage — advertises a member's keys before joining.

	Wire format: version(u16) + cipher_suite(u16) + init_key<V> + leaf_node + extensions<V> + signature<V>

	The init_key is an X25519 HPKE key used for the first KEM operation when
	adding this member. After joining, the leaf_node.encryption_key takes over.
	"""

	leaf_node: LeafNode
	init_key_pub: bytes  # X25519 one-time HPKE key (different from leaf_node.encryption_key)
	leaf_node_signature: bytes = b""  # kept for legacy compat; use leaf_node.signature

	_VERSION: int = 0x0001
	_CIPHER_SUITE: int = 0x0001

	# ------------------------------------------------------------------
	# Legacy compatibility shims (used by pre-v2 code)
	# ------------------------------------------------------------------
	@property
	def identity_key_pub(self) -> bytes:
		return self.leaf_node.signature_key

	def verify_signature(self) -> None:
		# 1. LeafNode signature (binds identity <-> encryption_key)
		self.leaf_node.verify_signature()
		# 2. KeyPackageTBS signature (RFC 9420 §10.1) — the only one covering init_key_pub.
		# Without this, a MITM can swap init_key_pub and hijack the Welcome (audit H1).
		if not self.leaf_node_signature:
			raise ValueError("KeyPackage has no signature")
		pub = ed25519.Ed25519PublicKey.from_public_bytes(self.leaf_node.signature_key)
		pub.verify(self.leaf_node_signature, self._tbs_bytes())  # raises InvalidSignature on tamper

	# ------------------------------------------------------------------
	# TBS / signing
	# ------------------------------------------------------------------
	def _tbs_bytes(self) -> bytes:
		"""KeyPackageTBS per RFC 9420 §10.1."""
		return (
			tls_u16(self._VERSION)
			+ tls_u16(self._CIPHER_SUITE)
			+ tls_opaque(self.init_key_pub)
			+ self.leaf_node.to_bytes()
			+ tls_varint(0)  # extensions<V> empty — must match to_bytes() wire encoding (audit L3)
		)

	# ------------------------------------------------------------------
	# Wire format
	# ------------------------------------------------------------------
	def to_bytes(self) -> bytes:
		"""RFC 9420 §10.1 TLS wire encoding."""
		return (
			tls_u16(self._VERSION)
			+ tls_u16(self._CIPHER_SUITE)
			+ tls_opaque(self.init_key_pub)  # HPKEPublicKey init_key<V>
			+ self.leaf_node.to_bytes()  # LeafNode leaf_node
			+ tls_varint(0)  # extensions<V> empty (RFC 9420 uses VarInt for <V>)
			+ tls_opaque(self.leaf_node_signature)  # signature<V>
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "KeyPackage":
		"""Parse from standalone bytes buffer (backward-compatible)."""
		obj, _ = cls.from_bytes_at(data, 0)
		return obj

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["KeyPackage", int]:
		version, offset = read_u16(data, offset)
		if version != cls._VERSION:
			raise ValueError(f"Unsupported KeyPackage version: {version:#06x}")
		cipher_suite, offset = read_u16(data, offset)
		if cipher_suite != cls._CIPHER_SUITE:
			raise ValueError(f"Unsupported cipher suite: {cipher_suite:#06x}")
		init_key_pub, offset = read_opaque(data, offset)
		leaf_node, offset = LeafNode.from_bytes_at(data, offset)
		# extensions<V> — per RFC 9420 uses VarInt prefix
		extensions, offset = read_extensions(data, offset)
		signature, offset = read_opaque(data, offset)
		return cls(
			leaf_node=leaf_node,
			init_key_pub=init_key_pub,
			leaf_node_signature=signature,
		), offset

	@classmethod
	def create(
		cls, encryption_key: bytes, init_key_pub: bytes, signature_key: bytes, identity: bytes, sign_fn: Callable[[bytes], bytes]
	) -> "KeyPackage":
		"""Factory: build and sign a complete KeyPackage.

		sign_fn(tbs_bytes) -> signature_bytes
		"""
		leaf_node = LeafNode.create(
			encryption_key=encryption_key,
			signature_key=signature_key,
			identity=identity,
			sign_fn=sign_fn,
		)
		kp = cls(leaf_node=leaf_node, init_key_pub=init_key_pub)
		# Sign the KeyPackageTBS with the same key
		kp_sig = sign_fn(kp._tbs_bytes())
		kp.leaf_node_signature = kp_sig
		return kp

	@classmethod
	def from_bytes_legacy(cls, data: bytes) -> "KeyPackage":
		"""Parse legacy (pre-v2.0) flat-format KeyPackage for migration only.

		Legacy format: identity_key(32) + init_key(32) [+ signature(64)]
		"""
		if len(data) == 64:
			identity_key = data[:32]
			init_key = data[32:64]
		elif len(data) == 128:
			identity_key = data[:32]
			init_key = data[32:64]
			# signature = data[64:128]  # discarded in migration
		else:
			raise ValueError(f"Invalid legacy KeyPackage size: {len(data)}")

		leaf_node = LeafNode(
			encryption_key=init_key,
			signature_key=identity_key,
			credential=Credential.basic(identity_key),  # identity = pub key bytes
			capabilities=Capabilities.default(),
		)
		return cls(leaf_node=leaf_node, init_key_pub=init_key)


# §7.3 ParentNode


@dataclass
class ParentNode:
	"""RFC 9420 §7.3: ParentNode — intermediate routing node in the tree.

	Wire format: encryption_key<V> + parent_hash<V> + unmerged_leaves<V>
	"""

	public_key: bytes  # X25519 HPKE public key
	parent_hash: bytes  # RFC 9420 §7.9 parent_hash (32 bytes)
	unmerged_leaves: list[int] = field(default_factory=list)  # uint32 leaf indices

	def unmerged_leaves_bytes(self) -> bytes:
		return b"".join(tls_u32(i) for i in self.unmerged_leaves)

	def to_bytes(self) -> bytes:
		"""RFC 9420 §7.3 encoding: public_key<V> + parent_hash<V> + control_field<V>."""
		return tls_opaque(self.public_key) + tls_opaque(self.parent_hash) + tls_opaque(self.unmerged_leaves_bytes())

	@classmethod
	def from_bytes(cls, data: bytes) -> "ParentNode":
		"""Parse from standalone bytes buffer (backward-compatible)."""
		obj, _ = cls.from_bytes_at(data, 0)
		return obj

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["ParentNode", int]:
		"""RFC 9420 §7.3 deserialization."""
		public_key, offset = read_opaque(data, offset)
		parent_hash, offset = read_opaque(data, offset)
		# RFC 9420 §7.3 unmerged_leaves<V> uses VarInt prefix
		unmerged_raw, offset = read_opaque(data, offset)
		unmerged = [int.from_bytes(unmerged_raw[i : i + 4], "big") for i in range(0, len(unmerged_raw), 4)]
		return cls(public_key=public_key, parent_hash=parent_hash, unmerged_leaves=unmerged), offset


# §7.4 RatchetTree
# RFC 9420 §7.4 wire format: optional<Node> ratchet_tree<V>
# Each entry is either:
#   0x00  (absent/blank node)
#   0x01  LeafNode
#   0x02  ParentNode


class RatchetTree:
	"""RFC 9420 §7.4: Left-balanced binary tree of Member keys.

	Array layout: leaves at even indices, parents at odd indices.
	to_bytes() / from_bytes() use the RFC §7.4 optional<Node> wire format.
	"""

	def __init__(self, num_leaves: int) -> None:
		self.num_leaves = num_leaves
		self.nodes: list[LeafNode | ParentNode | None] | tuple[LeafNode | ParentNode | None, ...] = (
			[None] * (2 * num_leaves - 1) if num_leaves > 0 else []
		)

	def freeze(self) -> None:
		if isinstance(self.nodes, list):
			self.nodes = tuple(self.nodes)

	def set_leaf(self, index: int, leaf: LeafNode) -> None:
		if index % 2 != 0:
			raise ValueError("Leaves must be at even indices")
		if isinstance(self.nodes, tuple):
			raise TypeError("RatchetTree is frozen")
		self.nodes[index] = leaf

	def set_parent(self, index: int, parent_node: ParentNode) -> None:
		if index % 2 == 0:
			raise ValueError("Parents must be at odd indices")
		if isinstance(self.nodes, tuple):
			raise TypeError("RatchetTree is frozen")
		self.nodes[index] = parent_node

	def blank_node(self, index: int) -> None:
		"""Blank (remove) the node at index, e.g. an ancestor on an added leaf's path."""
		if isinstance(self.nodes, tuple):
			raise TypeError("RatchetTree is frozen")
		if 0 <= index < len(self.nodes):
			self.nodes[index] = None

	def get_node(self, index: int) -> Optional[LeafNode | ParentNode]:
		if index < 0 or index >= len(self.nodes):
			return None
		return self.nodes[index]

	def expanded(self, new_num_leaves: int) -> "RatchetTree":
		"""Returns a new tree with more leaves, copying existing nodes."""
		if new_num_leaves < self.num_leaves:
			raise ValueError("Cannot contract tree with expanded()")
		new_tree = RatchetTree(new_num_leaves)
		for i, node in enumerate(self.nodes):
			if node is not None:
				if i % 2 == 0:
					assert isinstance(node, LeafNode)
					new_tree.set_leaf(i, node)
				else:
					assert isinstance(node, ParentNode)
					new_tree.set_parent(i, node)
		return new_tree

	def remove_leaf(self, leaf_index: int) -> "RatchetTree":
		"""RFC 9420 §7.7: Remove a member by blanking their leaf + direct path.

		1. Blank the leaf node at leaf_index (must be even).
		2. Blank all ancestors on the direct path to the root.
		3. Truncate trailing blank leaves to keep the tree minimal.

		Returns a new RatchetTree (does not mutate self if frozen).
		"""
		if leaf_index % 2 != 0:
			raise ValueError("leaf_index must be even (leaf node)")
		if leaf_index >= len(self.nodes):
			raise ValueError(f"leaf_index {leaf_index} out of bounds (tree has {len(self.nodes)} nodes)")

		# Work on a mutable copy
		tree = copy.deepcopy(self)
		if isinstance(tree.nodes, tuple):
			tree.nodes = list(tree.nodes)

		# Step 1: blank the leaf
		tree.nodes[leaf_index] = None

		# Step 2: blank all ancestors
		for ancestor in tree.direct_path(leaf_index):
			tree.nodes[ancestor] = None

		# Step 3: truncate trailing blank leaves
		# Find the rightmost non-blank leaf
		rightmost = -1
		for i in range(0, len(tree.nodes), 2):  # even indices = leaves
			if tree.nodes[i] is not None:
				rightmost = i

		if rightmost < 0:
			# All leaves blank — empty tree
			tree.num_leaves = 0
			tree.nodes = []
		else:
			# Tree size = 2 * num_leaves - 1
			new_num_leaves = (rightmost // 2) + 1
			new_size = 2 * new_num_leaves - 1
			tree.nodes = tree.nodes[:new_size]
			tree.num_leaves = new_num_leaves

		return tree

	def to_bytes(self) -> bytes:
		"""RFC 9420 §7.4, §13.4.3.2: ratchet_tree as optional<Node> nodes<V>.

		optional<Node>:
		- presence 0x00
		- presence 0x01 + NodeType + NodeBody
		"""
		parts = bytearray()
		for node in self.nodes:
			if node is None:
				parts += b"\x00"  # presence=0
			elif isinstance(node, LeafNode):
				# presence=1, type=leaf(1)
				parts += b"\x01\x01" + node.to_bytes()
			elif isinstance(node, ParentNode):
				# presence=1, type=parent(2)
				parts += b"\x01\x02" + node.to_bytes()

		# Return as a vector nodes<V> (struct RatchetTree wrapper)
		return tls_varint(len(parts)) + bytes(parts)

	@classmethod
	def _parse(cls, raw: bytes) -> "RatchetTree":
		"""Internal: parse the raw (already de-prefixed) optional<Node>[] bytes."""
		nodes: list[LeafNode | ParentNode | None] = []
		i = 0
		node_idx = 0
		while i < len(raw):
			present = raw[i]
			i += 1
			if present == 0x00:
				nodes.append(None)
			elif present == 0x01:
				if i >= len(raw):
					break
				node_type = raw[i]
				i += 1
				if node_type == 0x01:
					leaf, i = LeafNode.from_bytes_at(raw, i)
					nodes.append(leaf)
				elif node_type == 0x02:
					parent, i = ParentNode.from_bytes_at(raw, i)
					nodes.append(parent)
				else:
					raise ValueError(f"Unknown node type: {node_type:#04x}")
			else:
				raise ValueError(f"Invalid presence byte in RatchetTree: {present:#04x}")
			node_idx += 1
		num_leaves = (len(nodes) + 1) // 2
		tree = cls(num_leaves)
		tree.nodes = nodes
		return tree

	@classmethod
	def from_bytes(cls, data: bytes) -> "RatchetTree":
		"""Parse RFC 9420 §7.4 ratchet_tree (vector of optional nodes)."""
		# The extension content is a vector <optional<Node>>, so it has a length prefix.
		raw, _ = read_opaque(data, 0)
		return cls._parse(raw)

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["RatchetTree", int]:
		"""TLS streaming: parse ratchet_tree<V> from data at offset, return (tree, new_offset)."""
		raw, offset = read_opaque(data, offset)
		return cls._parse(raw), offset

	# ------------------------------------------------------------------
	# Tree math — RFC 9420 Appendix C (unchanged)
	# ------------------------------------------------------------------

	def level(self, index: int) -> int:
		"""RFC 9420 Appendix C: level(x) = number of trailing 1-bits."""
		if index < 0 or (index & 0x01 == 0):
			return 0
		k = 0
		while (index >> k) & 0x01 == 1 and k < 32:
			k += 1
		return k

	def _root(self) -> int:
		n = self.num_leaves
		if n <= 1:
			return 0
		w = 2 * n - 1
		k = w.bit_length()
		return (1 << (k - 1)) - 1

	def _parent(self, x: int) -> int:
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
		while p >= w:
			pk = self.level(p)
			p = p ^ ((0x01 << pk) | (((p >> (pk + 1)) & 0x01) << (pk + 1)))
		return p

	def _sibling(self, x: int) -> int:
		n = self.num_leaves
		if n <= 1:
			return x
		p = self._parent(x)
		k = self.level(p)
		if x < p:
			return p + (1 << (k - 1))
		else:
			return p - (1 << (k - 1))

	def direct_path(self, leaf_index: int) -> list[int]:
		"""RFC 9420 §7.1: ancestor nodes from leaf to root (exclusive of leaf)."""
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

	def filtered_direct_path(self, leaf_index: int) -> list[int]:
		"""RFC 9420 §4.1.2: direct_path filtered to exclude nodes where copath is completely blank."""
		dpath = self.direct_path(leaf_index)
		copath = self.copath(leaf_index)
		filtered = []
		for p, cp in zip(dpath, copath):
			if cp != -1 and len(self.resolution(cp)) > 0:
				filtered.append(p)
		return filtered

	def copath(self, leaf_index: int) -> list[int]:
		"""RFC 9420 §7.1.3: siblings of the direct_path nodes.

		Returns -1 for out-of-bounds siblings (used as blank sentinel).
		"""
		dpath = self.direct_path(leaf_index)
		n = len(self.nodes)
		copath = []
		x = leaf_index
		for p in dpath:
			sib = self._sibling(x)
			copath.append(sib if sib < n else -1)
			x = p
		return copath

	def resolution(self, index: int, _depth: int = 0) -> list[int]:
		"""RFC 9420 §7.2: resolution(x) = non-blank subtree members."""
		if _depth > 32:
			raise RuntimeError(f"Infinite recursion in resolution for index {index}")
		if index < 0 or index >= len(self.nodes):
			return []
		node = self.nodes[index]
		if index % 2 == 0:
			return [index] if node is not None else []
		lvl = self.level(index)
		left = index - (1 << (lvl - 1))
		right = index + (1 << (lvl - 1))
		if self.nodes[index] is None:
			return self.resolution(left, _depth + 1) + self.resolution(right, _depth + 1)
		unmerged = node.unmerged_leaves if isinstance(node, ParentNode) else []
		# unmerged_leaves are leaf indices; a resolution is a list of node indices (audit M5)
		return [index] + [2 * leaf for leaf in unmerged]

	def tree_hash(self) -> bytes:
		"""RFC 9420 §7.8: Recursive hash of the tree structure.

		Returns the SHA-256 hash of the root node.
		"""
		if not self.nodes:
			return hashlib.sha256(b"").digest()
		return self._node_hash(self._root())

	def _node_hash(self, index: int) -> bytes:
		"""Internal recursive helper for tree_hash."""
		if index < 0 or index >= len(self.nodes):
			return hashlib.sha256(b"\x00").digest()  # treat as blank leaf
		node = self.nodes[index]
		w = len(self.nodes)

		if index % 2 == 0:  # Leaf
			# RFC 9420 §7.8 LeafNodeHashInput: node_type(leaf) + uint32 leaf_index + optional<LeafNode>.
			# audit tree_hash: the leaf_index was previously omitted, so tree_hash() never matched
			# a conforming implementation (OpenMLS). leaf_index = node_index / 2.
			res = b"\x01" + tls_u32(index // 2)
			if node is None:
				res += b"\x00"
			else:
				res += b"\x01" + node.to_bytes()
			return hashlib.sha256(res).digest()
		else:  # Parent
			# TreeHashInput (type=2) + optional<ParentNode> + left_hash<V> + right_hash<V>
			lvl = self.level(index)
			left_idx = index - (1 << (lvl - 1))
			right_idx = index + (1 << (lvl - 1))

			# LBBT: If right child is out of bounds, ratchet down the left path
			# of the right subtree until we hit a node that exists.
			while right_idx >= w and lvl > 0:
				lvl_r = self.level(right_idx)
				if lvl_r == 0:
					right_idx -= 1
					break
				right_idx = right_idx - (1 << (lvl_r - 1))

			left_h = self._node_hash(left_idx)
			right_h = self._node_hash(right_idx)

			res = b"\x02"
			if node is None:
				res += b"\x00"
			else:
				res += b"\x01" + node.to_bytes()

			# Opaque hashes use project-standard VarInt prefix
			res += tls_opaque(left_h)
			res += tls_opaque(right_h)
			return hashlib.sha256(res).digest()
