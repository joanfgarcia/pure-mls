"""RFC 9420 §9: SecretTree and per-message key/nonce derivation.

The SecretTree converts an epoch's encryption_secret into per-leaf,
per-generation symmetric keys (content_key, content_nonce) for
encrypting/decrypting PrivateMessage payloads.

RFC §9.3 Binary-Tree Derivation Path:
	root = encryption_secret
	parent -> left  = ExpandWithLabel(parent, "left",  b"", NH)
	parent -> right = ExpandWithLabel(parent, "right", b"", NH)
	leaf_secret[leaf]  = ExpandWithLabel(leaf_node, "application", b"", NH)
	leaf_secret per-generation ratcheting adds the generation as context:
	next = ExpandWithLabel(current, "application", I2OSP(gen, 4), NH).
	key   = ExpandWithLabel(leaf_secret[gen], "key",   b"", KEY_LEN)
	nonce = ExpandWithLabel(leaf_secret[gen], "nonce", b"", NONCE_LEN)

SenderData (§9.4): sender_data_secret -> sd_key / sd_nonce via ExpandWithLabel.

Note: AES-128-GCM (16-byte key) per MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
"""

from dataclasses import dataclass, field

from pure_mls.hkdf import expand_with_label

_KEY_LEN: int = 16  # AES-128-GCM key (bytes)
_NONCE_LEN: int = 12  # AEAD nonce (bytes)
_NH: int = 32  # Hash output length


def _tree_width(n_leaves: int) -> int:
	"""Smallest power-of-2 >= n_leaves (number of tree slots at leaf level)."""
	w = 1
	while w < n_leaves:
		w <<= 1
	return w


def _derive_leaf_node_secret(encryption_secret: bytes, leaf_index: int, n_leaves: int) -> bytes:
	"""RFC §9.3: traverse the binary tree from root to the given leaf.

	The tree has `w = _tree_width(n_leaves)` leaf slots.
	Root secret = encryption_secret.
	At each level: go left (bit=0) or right (bit=1) based on the bit of leaf_index,
	reading from MSB to LSB for the current tree depth.
	"""
	w = _tree_width(n_leaves)
	depth = 0
	tmp = w
	while tmp > 1:
		depth += 1
		tmp >>= 1

	secret = encryption_secret
	for bit_pos in range(depth - 1, -1, -1):
		bit = (leaf_index >> bit_pos) & 1
		direction = "right" if bit else "left"
		secret = expand_with_label(secret, direction, b"", _NH)

	return secret


@dataclass
class SecretTree:
	"""Per-epoch SecretTree state (RFC 9420 §9).

	Holds next-to-use generation for each leaf. Derives keys on demand
	and advances the generation counter to enforce forward secrecy.
	Uses RFC §9.3 binary-tree derivation for IETF vector compliance.
	"""

	encryption_secret: bytes
	n_leaves: int
	_generations: dict[int, int] = field(default_factory=dict)
	_ratchet_cache: dict[tuple[int, int], bytes] = field(default_factory=dict)

	def _leaf_node_secret(self, leaf_index: int) -> bytes:
		"""RFC §9.3: root -> binary-tree path -> leaf node secret."""
		return _derive_leaf_node_secret(self.encryption_secret, leaf_index, self.n_leaves)

	def _leaf_secret_for_gen(self, leaf_index: int, generation: int) -> bytes:
		"""RFC §9.3: leaf_node_secret ratcheted to the given generation.

		gen_N_secret = ExpandWithLabel(gen_N-1_secret, "application", I2OSP(N, 4), NH)
		"""
		key = (leaf_index, generation)
		if key in self._ratchet_cache:
			return self._ratchet_cache.pop(key)
		# Build from leaf_node_secret
		secret = self._leaf_node_secret(leaf_index)
		for gen in range(generation + 1):
			secret = expand_with_label(secret, "application", gen.to_bytes(4, "big"), _NH)
		return secret

	def get_key_and_nonce(self, leaf_index: int) -> tuple[bytes, bytes, int]:
		"""Derive (content_key, content_nonce, generation) for the next message from leaf_index.

		Advances the internal generation counter for that leaf
		(forward secrecy: old generations cannot be rederived).
		Returns the generation used so the sender can include it in SenderData.
		"""
		gen = self._generations.get(leaf_index, 0)
		leaf_secret = self._leaf_secret_for_gen(leaf_index, gen)
		key = expand_with_label(leaf_secret, "key", b"", _KEY_LEN)
		nonce = expand_with_label(leaf_secret, "nonce", b"", _NONCE_LEN)
		self._generations[leaf_index] = gen + 1
		return key, nonce, gen

	def get_key_and_nonce_for_gen(self, leaf_index: int, generation: int) -> tuple[bytes, bytes]:
		"""Derive (content_key, content_nonce) for a specific generation (receiver side).

		Raises ValueError if this generation was already consumed (forward secrecy).
		"""
		current_gen = self._generations.get(leaf_index, 0)
		if generation < current_gen:
			raise ValueError(
				f"SecretTree: leaf {leaf_index} generation {generation} already consumed (current={current_gen}) — forward secrecy violated"
			)
		leaf_secret = self._leaf_secret_for_gen(leaf_index, generation)
		self._generations[leaf_index] = generation + 1
		key = expand_with_label(leaf_secret, "key", b"", _KEY_LEN)
		nonce = expand_with_label(leaf_secret, "nonce", b"", _NONCE_LEN)
		return key, nonce

	def wipe(self) -> None:
		"""Zero all key material for this epoch (RFC 9420 §9 forward secrecy)."""
		self.encryption_secret = b"\x00" * len(self.encryption_secret)
		self._ratchet_cache.clear()
		self._generations.clear()


def derive_sender_data_key(sender_data_secret: bytes, ciphertext_sample: bytes) -> bytes:
	"""RFC 9420 §9.4: SenderDataKey = ExpandWithLabel(SenderDataSecret, 'key', sample, 16)."""
	return expand_with_label(sender_data_secret, "key", ciphertext_sample, _KEY_LEN)


def derive_sender_data_nonce(sender_data_secret: bytes, ciphertext_sample: bytes) -> bytes:
	"""RFC 9420 §9.4: SenderDataNonce = ExpandWithLabel(SenderDataSecret, 'nonce', sample, 12)."""
	return expand_with_label(sender_data_secret, "nonce", ciphertext_sample, _NONCE_LEN)
