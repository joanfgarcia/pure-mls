"""RFC 9420 §9: SecretTree and per-message key/nonce derivation.

The SecretTree converts an epoch's encryption_secret into per-leaf,
per-generation symmetric keys (content_key, content_nonce) for
encrypting/decrypting PrivateMessage payloads.
"""

import struct
from dataclasses import dataclass, field

from pure_mls.hkdf import expand_with_label

_KEY_LEN: int = 16  # AES-128-GCM key (bytes)
_NONCE_LEN: int = 12  # AEAD nonce (bytes)
_NH: int = 32  # Hash output length


def _log2(x: int) -> int:
	"""Return the log2 of x, matching RFC §13.1."""
	if x == 0:
		return 0
	return x.bit_length() - 1


def _level(index: int) -> int:
	"""Return the level of a node in the tree (RFC §13.1)."""
	if (index & 0x01) == 0:
		return 0
	k = 0
	while ((index >> k) & 0x01) == 1:
		k += 1
	return k


def _root(n_leaves: int) -> int:
	"""Return the root node index for a tree with n_leaves (RFC §13.1)."""
	n = 2 * n_leaves - 1
	return (1 << _log2(n)) - 1


def _left(index: int) -> int:
	"""Return the left child of a parent node (RFC §13.1)."""
	k = _level(index)
	return index ^ (0x01 << (k - 1))


def _right(index: int) -> int:
	"""Return the right child of a parent node (RFC §13.1)."""
	k = _level(index)
	return index ^ (0x03 << (k - 1))


def _parent(index: int, n_leaves: int) -> int:
	"""Return the parent of a node, reparenting for non-complete trees (RFC App. C).

	audit M6: the previous version ignored n_leaves and never reparented, so for
	group sizes that are not a power of two it routed through phantom nodes and
	derived per-leaf secrets down the wrong path.
	"""
	if n_leaves <= 1:
		return 0
	w = 2 * n_leaves - 1
	r = _root(n_leaves)
	if index == r:
		return index
	k = _level(index)
	b = (index >> (k + 1)) & 0x01
	p = index ^ ((0x01 << k) | (b << (k + 1)))
	while p >= w:
		pk = _level(p)
		p = p ^ ((0x01 << pk) | (((p >> (pk + 1)) & 0x01) << (pk + 1)))
	return p


def _get_path(target_leaf_index: int, n_leaves: int) -> list[str]:
	"""Compute the path from root to leaf, returning a list of 'left'/'right' directions."""
	target_node = target_leaf_index * 2
	root_node = _root(n_leaves)
	path = []
	curr = target_node
	depth = 0
	while curr != root_node and depth < 32:
		p = _parent(curr, n_leaves)
		if curr == _left(p):
			path.append("left")
		else:
			path.append("right")
		curr = p
		depth += 1
	path.reverse()
	return path


@dataclass
class SecretTree:
	"""Per-epoch SecretTree state (RFC 9420 §9).

	Holds next-to-use generation for each leaf. Derives keys on demand
	and advances the generation counter to enforce forward secrecy.
	"""

	encryption_secret: bytes | bytearray  # P2-1: mutable — allows in-place zeroing
	n_leaves: int
	_generations: dict[int, int] = field(default_factory=dict)
	# Cache for the latest derived secret per leaf to optimize forward ratcheting
	# (leaf_index) -> (generation, type, secret)
	# P2-1: secret stored as bytearray for zeroing
	_leaf_cache: dict[int, dict[str, tuple[int, bytearray]]] = field(default_factory=dict)

	def __post_init__(self) -> None:
		# Ensure encryption_secret is a mutable bytearray for secure zeroing
		if not isinstance(self.encryption_secret, bytearray):
			self.encryption_secret = bytearray(self.encryption_secret)

	def __repr__(self) -> str:
		# audit M8: never render the raw encryption_secret via the default dataclass repr
		return f"<SecretTree n_leaves={self.n_leaves} secret redacted>"

	def _derive_leaf_node_secret(self, leaf_index: int) -> bytes:
		"""Traverse §9.3 binary tree from root encryption_secret to leaf node."""
		path = _get_path(leaf_index, self.n_leaves)
		secret = bytes(self.encryption_secret)
		for direction in path:
			# OpenMLS/IETF parity: label="tree", context=direction (b"left"/b"right")
			# although RFC 9420 §9.3 says label=direction, context=b""
			secret = expand_with_label(secret, "tree", direction.encode(), _NH)
		return secret

	def _get_ratchet_secret(self, leaf_index: int, generation: int, secret_type: str) -> bytes:
		"""Derive ratchet secret for a specific leaf/gen/type (§10.1)."""
		# secret_type is "handshake" or "application"

		# Check cache first
		cache = self._leaf_cache.setdefault(leaf_index, {})
		tip_gen, tip_secret = cache.get(secret_type, (-1, bytearray()))

		if tip_gen == generation:
			return bytes(tip_secret)

		if generation < tip_gen:
			raise ValueError(f"SecretTree forward-secrecy: gen {generation} < tip {tip_gen}")

		# Start from tip or from leaf node secret (gen 0 split)
		if tip_gen >= 0:
			curr_gen = tip_gen
			curr_secret = bytes(tip_secret)
		else:
			# §9.2: split happens at the leaf node secret
			node_secret = self._derive_leaf_node_secret(leaf_index)
			# Gen 0 secret = ExpandWithLabel(node_secret, type, b"", NH)
			curr_secret = expand_with_label(node_secret, secret_type, b"", _NH)
			curr_gen = 0

		# Ratchet forward (§10.1 DeriveTreeSecret)
		for g in range(curr_gen, generation):
			# OpenMLS/IETF parity: ratchet label is ALWAYS "secret"
			# context = struct { uint32 generation; }
			context = struct.pack("!I", g)
			curr_secret = expand_with_label(curr_secret, "secret", context, _NH)

		# Update cache
		cache[secret_type] = (generation, bytearray(curr_secret))
		return curr_secret

	def get_key_and_nonce_for_gen(self, leaf_index: int, generation: int, secret_type: str = "application") -> tuple[bytes, bytes]:
		"""Non-consuming derivation for a specific generation (receiver side)."""
		ratchet_secret = self._get_ratchet_secret(leaf_index, generation, secret_type)
		# §9.3: key/nonce from ratchet secret
		# context = struct { uint32 generation; }
		context = struct.pack("!I", generation)
		key = expand_with_label(ratchet_secret, "key", context, _KEY_LEN)
		nonce = expand_with_label(ratchet_secret, "nonce", context, _NONCE_LEN)
		return key, nonce

	def get_key_and_nonce(self, leaf_index: int, secret_type: str = "application") -> tuple[bytes, bytes, int]:
		"""Consuming derivation (sender side). Advances generation counter."""
		gen = self._generations.get(leaf_index, 0)
		key, nonce = self.get_key_and_nonce_for_gen(leaf_index, gen, secret_type)
		self._generations[leaf_index] = gen + 1
		return key, nonce, gen

	def wipe(self) -> None:
		"""Securely zero all sensitive data (RFC 9420 §9)."""
		assert isinstance(self.encryption_secret, bytearray)
		self.encryption_secret[:] = b"\x00" * len(self.encryption_secret)
		for leaf_data in self._leaf_cache.values():
			for _gen, secret in leaf_data.values():
				secret[:] = b"\x00" * len(secret)
		self._leaf_cache.clear()
		self._generations.clear()


def derive_sender_data_key(sender_data_secret: bytes, ciphertext_sample: bytes) -> bytes:
	"""RFC 9420 §9.4: SenderDataKey = ExpandWithLabel(SenderDataSecret, 'key', sample, 16)."""
	return expand_with_label(sender_data_secret, "key", ciphertext_sample, _KEY_LEN)


def derive_sender_data_nonce(sender_data_secret: bytes, ciphertext_sample: bytes) -> bytes:
	"""RFC 9420 §9.4: SenderDataNonce = ExpandWithLabel(SenderDataSecret, 'nonce', sample, 12)."""
	return expand_with_label(sender_data_secret, "nonce", ciphertext_sample, _NONCE_LEN)
