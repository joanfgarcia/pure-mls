"""RFC 9420 §9: SecretTree and per-message key/nonce derivation.

The SecretTree converts an epoch's encryption_secret into per-leaf,
per-generation symmetric keys (content_key, content_nonce) for
encrypting/decrypting PrivateMessage payloads.

Derivation chain (§9.3):
    encryption_secret
      └─ tree_node_secret[leaf]  = ExpandWithLabel(encryption_secret, "tree", leaf_bytes(4), NH)
           └─ leaf_secret[gen]   = ExpandWithLabel(tree_node_secret, "application", gen_bytes(4), NH)
                ├─ content_key   = ExpandWithLabel(leaf_secret, "key",   b"", AES128_KEY_LEN=16)
                └─ content_nonce = ExpandWithLabel(leaf_secret, "nonce", b"", 12)

SenderData encryption (§9.4):
    sender_data_secret
      ├─ sd_key   = ExpandWithLabel(sender_data_secret, "key",   ciphertext_sample, 16)
      └─ sd_nonce = ExpandWithLabel(sender_data_secret, "nonce", ciphertext_sample, 12)

Note: AES-128-GCM is used (16-byte key) per
      MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 ciphersuite.
"""

import struct
from dataclasses import dataclass, field

from pure_mls.hkdf import expand_with_label

_KEY_LEN: int = 16  # AES-128-GCM key (bytes)
_NONCE_LEN: int = 12  # AEAD nonce (bytes)
_NH: int = 32  # Hash output length


@dataclass
class SecretTree:
	"""Per-epoch SecretTree state.

	Holds next-to-use generation for each leaf. Derives keys on demand
	and advances the generation counter to enforce forward secrecy.
	"""

	encryption_secret: bytes
	n_leaves: int
	_generations: dict[int, int] = field(default_factory=dict)
	_ratchet_cache: dict[tuple[int, int], bytes] = field(default_factory=dict)

	def _tree_node_secret(self, leaf_index: int) -> bytes:
		"""ExpandWithLabel(encryption_secret, 'tree', leaf_bytes(4), NH)."""
		context = struct.pack(">I", leaf_index)
		return expand_with_label(self.encryption_secret, "tree", context, _NH)

	def _leaf_secret(self, leaf_index: int, generation: int) -> bytes:
		"""ExpandWithLabel(tree_node_secret, 'application', gen_bytes(4), NH)."""
		key = (leaf_index, generation)
		if key in self._ratchet_cache:
			return self._ratchet_cache.pop(key)
		base = self._tree_node_secret(leaf_index)
		context = struct.pack(">I", generation)
		return expand_with_label(base, "application", context, _NH)

	def get_key_and_nonce(self, leaf_index: int) -> tuple[bytes, bytes, int]:
		"""Derive (content_key, content_nonce, generation) for the next message from leaf_index.

		Advances the internal generation counter for that leaf
		(forward secrecy: old generations cannot be rederived).
		Returns the generation used so the sender can include it in SenderData.
		"""
		gen = self._generations.get(leaf_index, 0)
		leaf_secret = self._leaf_secret(leaf_index, gen)
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
		leaf_secret = self._leaf_secret(leaf_index, generation)
		self._generations[leaf_index] = generation + 1
		key = expand_with_label(leaf_secret, "key", b"", _KEY_LEN)
		nonce = expand_with_label(leaf_secret, "nonce", b"", _NONCE_LEN)
		return key, nonce


def derive_sender_data_key(sender_data_secret: bytes, ciphertext_sample: bytes) -> bytes:
	"""RFC 9420 §9.4: SenderDataKey = ExpandWithLabel(SenderDataSecret, 'key', sample, 16)."""
	return expand_with_label(sender_data_secret, "key", ciphertext_sample, _KEY_LEN)


def derive_sender_data_nonce(sender_data_secret: bytes, ciphertext_sample: bytes) -> bytes:
	"""RFC 9420 §9.4: SenderDataNonce = ExpandWithLabel(SenderDataSecret, 'nonce', sample, 12)."""
	return expand_with_label(sender_data_secret, "nonce", ciphertext_sample, _NONCE_LEN)
