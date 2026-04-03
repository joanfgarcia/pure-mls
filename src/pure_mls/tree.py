"""RFC 9420 Tree structures: Credential, Capabilities, LeafNode, KeyPackage, RatchetTree.

All to_bytes() / from_bytes() methods produce RFC 9420 wire format, compatible
with OpenMLS (Rust), mlspp (C++), and any other RFC-conforming implementation.

§7.2   LeafNode
§10.1  KeyPackage
§7.4   RatchetTree optional<Node> encoding
"""

import copy
from dataclasses import dataclass, field, replace
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from pure_mls.tls import (
	read_opaque,
	read_opaque32,
	read_u8,
	read_u16,
	read_u32,
	tls_opaque,
	tls_opaque32,
	tls_u8,
	tls_u16,
	tls_u32,
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


# §7.2 Capabilities


@dataclass
class Capabilities:
	"""RFC 9420 §7.2: Capabilities declares supported protocol features.

	For pure-mls v2.0 we declare the single supported ciphersuite.
	"""

	versions: list[int] = field(default_factory=lambda: [0x0001])  # mls10
	cipher_suites: list[int] = field(default_factory=lambda: [0x0001])  # MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
	extensions: list[int] = field(default_factory=list)
	proposals: list[int] = field(default_factory=list)
	credentials: list[int] = field(default_factory=lambda: [CREDENTIAL_TYPE_BASIC])

	def to_bytes(self) -> bytes:
		"""TLS: each field is a uint16-prefixed vector of uint16 values."""

		def u16_vec(lst: list[int]) -> bytes:
			inner = b"".join(tls_u16(v) for v in lst)
			return tls_opaque(inner)

		return u16_vec(self.versions) + u16_vec(self.cipher_suites) + u16_vec(self.extensions) + u16_vec(self.proposals) + u16_vec(self.credentials)

	@classmethod
	def from_bytes(cls, data: bytes) -> "Capabilities":
		"""Parse from standalone bytes buffer (backward-compatible)."""
		obj, _ = cls.from_bytes_at(data, 0)
		return obj

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["Capabilities", int]:
		def read_u16_vec(buf: bytes, off: int) -> tuple[list[int], int]:
			raw, off = read_opaque(buf, off)
			values = [int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2)]
			return values, off

		versions, offset = read_u16_vec(data, offset)
		cipher_suites, offset = read_u16_vec(data, offset)
		extensions, offset = read_u16_vec(data, offset)
		proposals, offset = read_u16_vec(data, offset)
		credentials, offset = read_u16_vec(data, offset)
		return cls(
			versions=versions,
			cipher_suites=cipher_suites,
			extensions=extensions,
			proposals=proposals,
			credentials=credentials,
		), offset

	@classmethod
	def default(cls) -> "Capabilities":
		return cls()


# §7.2 LeafNodeSource

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
	extensions: bytes = b""  # TLS-encoded extensions vector (empty = 4 zero bytes)
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
		"""LeafNodeTBS per RFC 9420 §7.2.

		For key_package source: no group_id / leaf_index.
		For update / commit source: includes group_id and leaf_index.
		"""
		tbs = (
			tls_u16(_CIPHER_SUITE)
			+ tls_opaque(self.encryption_key)
			+ tls_opaque(self.signature_key)
			+ self.credential.to_bytes()
			+ self.capabilities.to_bytes()
			+ tls_u8(self.leaf_node_source)
			+ (self.extensions or tls_u32(0))  # extensions<V> (empty = uint32 zero)
		)
		if self.leaf_node_source in (LEAF_NODE_SOURCE_UPDATE, LEAF_NODE_SOURCE_COMMIT):
			tbs += tls_opaque(group_id) + tls_u32(leaf_index)
		return tbs

	def sign(self, sign_fn: Callable[[bytes], bytes], group_id: bytes = b"", leaf_index: int = 0) -> "LeafNode":
		"""Return a signed copy of this LeafNode."""

		tbs = self._tbs_bytes(group_id, leaf_index)
		return replace(self, signature=sign_fn(tbs))

	def verify_signature(self, group_id: bytes = b"", leaf_index: int = 0) -> None:
		"""Verify the Ed25519 signature on this LeafNode.

		P1-04 fix: the TBS content depends on leaf_node_source (RFC 9420 §7.2):
		- 0x01 key_package: TBS does NOT include group_id / leaf_index.
		- 0x02 update / 0x03 commit: TBS MUST include group_id and leaf_index.
		Callers must supply group_id and leaf_index when verifying non-KeyPackage leaves.
		"""

		if not self.signature:
			raise ValueError("LeafNode has no signature")
		pub = ed25519.Ed25519PublicKey.from_public_bytes(self.signature_key)
		tbs = self._tbs_bytes(group_id=group_id, leaf_index=leaf_index)
		pub.verify(self.signature, tbs)

	def to_bytes(self) -> bytes:
		"""RFC 9420 §7.2 TLS wire encoding of LeafNode."""
		return (
			tls_opaque(self.encryption_key)  # HPKEPublicKey encryption_key<V>
			+ tls_opaque(self.signature_key)  # SignaturePublicKey signature_key<V>
			+ self.credential.to_bytes()  # Credential credential
			+ self.capabilities.to_bytes()  # Capabilities capabilities
			+ tls_u8(self.leaf_node_source)  # LeafNodeSource leaf_node_source
			+ (self.extensions if self.extensions else tls_u32(0))  # extensions<V>
			+ tls_opaque(self.signature)  # opaque signature<V>
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "LeafNode":
		"""Parse from standalone bytes buffer (backward-compatible)."""
		obj, _ = cls.from_bytes_at(data, 0)
		return obj

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["LeafNode", int]:
		encryption_key, offset = read_opaque(data, offset)
		signature_key, offset = read_opaque(data, offset)
		credential, offset = Credential.from_bytes_at(data, offset)
		capabilities, offset = Capabilities.from_bytes_at(data, offset)
		leaf_node_source, offset = read_u8(data, offset)
		# extensions<V> — read as raw bytes (uint32-prefixed)
		ext_raw, offset = read_opaque32(data, offset)
		signature, offset = read_opaque(data, offset)
		return cls(
			encryption_key=encryption_key,
			signature_key=signature_key,
			credential=credential,
			capabilities=capabilities,
			leaf_node_source=leaf_node_source,
			extensions=ext_raw,
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
		self.leaf_node.verify_signature()

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
			+ tls_u32(0)  # extensions<V> empty
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
			+ tls_u32(0)  # extensions<V> empty
			+ tls_opaque(self.leaf_node.signature)  # signature<V>
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
		# extensions<V> (uint32-prefixed) — read and discard
		ext_len, offset = read_u32(data, offset)
		offset += ext_len
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

	def to_bytes(self) -> bytes:
		"""RFC 9420 §7.3 TLS encoding."""
		unmerged = b"".join(tls_u32(i) for i in self.unmerged_leaves)
		return (
			tls_opaque(self.public_key)  # HPKEPublicKey encryption_key<V>
			+ tls_opaque(self.parent_hash)  # opaque parent_hash<V>
			+ tls_opaque32(unmerged)  # uint32 unmerged_leaves<V>
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "ParentNode":
		"""Parse from standalone bytes buffer (backward-compatible)."""
		obj, _ = cls.from_bytes_at(data, 0)
		return obj

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["ParentNode", int]:
		public_key, offset = read_opaque(data, offset)
		parent_hash, offset = read_opaque(data, offset)
		unmerged_raw, offset = read_opaque32(data, offset)
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

	def get_node(self, index: int) -> Optional[LeafNode | ParentNode]:
		if index < 0 or index >= len(self.nodes):
			return None
		return self.nodes[index]

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
		"""RFC 9420 §7.4: ratchet_tree as optional<Node>[] (uint32-prefixed vector).

		Each slot: 0x00=blank, 0x01=LeafNode, 0x02=ParentNode.
		"""
		parts = bytearray()
		for node in self.nodes:
			if node is None:
				parts += b"\x00"
			elif isinstance(node, LeafNode):
				encoded = node.to_bytes()
				parts += b"\x01" + encoded
			elif isinstance(node, ParentNode):
				encoded = node.to_bytes()
				parts += b"\x02" + encoded
		return tls_opaque32(bytes(parts))

	@classmethod
	def _parse(cls, raw: bytes) -> "RatchetTree":
		"""Internal: parse the raw (already de-prefixed) optional<Node>[] bytes."""
		nodes: list[LeafNode | ParentNode | None] = []
		i = 0
		while i < len(raw):
			node_type = raw[i]
			i += 1
			if node_type == 0x00:
				nodes.append(None)
			elif node_type == 0x01:
				leaf, i = LeafNode.from_bytes_at(raw, i)
				nodes.append(leaf)
			elif node_type == 0x02:
				parent, i = ParentNode.from_bytes_at(raw, i)
				nodes.append(parent)
			else:
				raise ValueError(f"Unknown node type: {node_type:#04x}")
		num_leaves = (len(nodes) + 1) // 2
		tree = cls(num_leaves)
		tree.nodes = nodes
		return tree

	@classmethod
	def from_bytes(cls, data: bytes) -> "RatchetTree":
		"""Backward-compatible: parse RFC §7.4 ratchet_tree<V> from a standalone buffer."""
		raw, _ = read_opaque32(data, 0)
		return cls._parse(raw)

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["RatchetTree", int]:
		"""TLS streaming: parse ratchet_tree<V> from data at offset, return (tree, new_offset)."""
		raw, offset = read_opaque32(data, offset)
		return cls._parse(raw), offset

	# ------------------------------------------------------------------
	# Tree math — RFC 9420 Appendix C (unchanged)
	# ------------------------------------------------------------------

	def level(self, index: int) -> int:
		"""RFC 9420 Appendix C: level(x) = number of trailing 1-bits."""
		if index & 0x01 == 0:
			return 0
		k = 0
		while (index >> k) & 0x01 == 1:
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
			pb = (p >> (pk + 1)) & 0x01
			p = p ^ ((0x01 << pk) | (pb << (pk + 1)))
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

	def resolution(self, index: int) -> list[int]:
		"""RFC 9420 §7.2: resolution(x) = non-blank subtree members."""
		if index < 0 or index >= len(self.nodes):
			return []
		node = self.nodes[index]
		if index % 2 == 0:
			return [index] if node is not None else []
		lvl = self.level(index)
		left = index - (1 << (lvl - 1))
		right = index + (1 << (lvl - 1))
		if self.nodes[index] is None:
			return self.resolution(left) + self.resolution(right)
		unmerged = node.unmerged_leaves if isinstance(node, ParentNode) else []
		return [index] + list(unmerged)
