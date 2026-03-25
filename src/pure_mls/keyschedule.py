import hashlib
from dataclasses import dataclass

from pure_mls.hkdf import encode_varint, hkdf_expand, hkdf_extract


@dataclass
class KeySchedule:
	"""
	Immutable object holding the symmetric cryptographic state for a single Epoch.
	Derived strictly from RFC 9420 Section 8 (Key Schedule).
	"""

	joiner_secret: bytes
	epoch_secret: bytes
	sender_data_secret: bytes
	encryption_secret: bytes
	exporter_secret: bytes
	epoch_authenticator: bytes
	external_secret: bytes
	confirmation_key: bytes
	next_init_secret: bytes

	SIZE = 288

	@staticmethod
	def _expand_with_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
		"""RFC 9420 §8: ExpandWithLabel using KDFLabel struct.

		KDFLabel = uint16(length) + opaque<V>(label) + opaque<V>(context)
		where <V> is MLS variable-length encoding (QUIC-style varints, RFC 9000).
		This is confirmed by the official IETF key schedule test vectors.
		"""
		full_label = b"MLS 1.0 " + label
		hkdf_label = (
			length.to_bytes(2, "big")  # uint16  length
			+ encode_varint(len(full_label))  # varint  len(label)
			+ full_label  # label bytes
			+ encode_varint(len(context))  # varint  len(context)
			+ context  # context bytes
		)
		return hkdf_expand(secret, hkdf_label, length, hashlib.sha256)

	@classmethod
	def derive(
		cls,
		init_secret: bytes,
		commit_secret: bytes,
		group_context: bytes,
		psk_secret: bytes | None = None,
	) -> "KeySchedule":
		"""
		Derives all epoch cryptographic materials from a previous init_secret
		mixed with the newly injected commit_secret (TreeKEM root hash) and optional PSK.
		"""
		# 1. Joiner Secret: KDF.Extract(init_secret, commit_secret) + ExpandWithLabel("joiner")
		pre_joiner_secret = hkdf_extract(init_secret, commit_secret, hashlib.sha256)
		joiner_secret = cls._expand_with_label(pre_joiner_secret, b"joiner", group_context, 32)

		# 2. Member Secret: KDF.Extract(joiner_secret, psk_secret)
		if psk_secret is None:
			psk_secret = b"\x00" * 32
		member_secret = hkdf_extract(joiner_secret, psk_secret, hashlib.sha256)

		# 3. Epoch Secret: ExpandWithLabel(member_secret, "epoch", GroupContext)
		epoch_secret = cls._expand_with_label(member_secret, b"epoch", group_context, 32)

		return cls._from_epoch_secret(epoch_secret, joiner_secret)

	@classmethod
	def _from_epoch_secret(cls, epoch_secret: bytes, joiner_secret: bytes) -> "KeySchedule":
		"""
		Constructs the full schedule from an already derived epoch_secret.
		Used by both the committer (derive) and joiner (MLSGroup.join).
		"""
		return cls(
			joiner_secret=joiner_secret,
			epoch_secret=epoch_secret,
			sender_data_secret=cls._expand_with_label(epoch_secret, b"sender data", b"", 32),
			encryption_secret=cls._expand_with_label(epoch_secret, b"encryption", b"", 32),
			exporter_secret=cls._expand_with_label(epoch_secret, b"exporter", b"", 32),
			epoch_authenticator=cls._expand_with_label(epoch_secret, b"authentication", b"", 32),
			external_secret=cls._expand_with_label(epoch_secret, b"external", b"", 32),
			confirmation_key=cls._expand_with_label(epoch_secret, b"confirm", b"", 32),
			next_init_secret=cls._expand_with_label(epoch_secret, b"init", b"", 32),
		)

	@classmethod
	def derive_welcome_key(cls, joiner_secret: bytes, context: bytes) -> bytes:
		"""RFC 9420 §12.1.2: welcome_key = ExpandWithLabel(joiner_secret, "welcome", context, 16)."""
		return cls._expand_with_label(joiner_secret, b"welcome", context, 16)

	@classmethod
	def derive_welcome_nonce(cls, joiner_secret: bytes, context: bytes) -> bytes:
		"""RFC 9420 §12.1.2: welcome_nonce = ExpandWithLabel(joiner_secret, "nonce", context, 12)."""
		return cls._expand_with_label(joiner_secret, b"nonce", context, 12)

	@classmethod
	def derive_membership_key(cls, epoch_secret: bytes) -> bytes:
		"""RFC 9420 §8.1: membership_key = ExpandWithLabel(epoch_secret, 'membership', b'', 32).

		Confirmed by IETF key schedule test vectors: input is epoch_secret, not epoch_authenticator.
		"""
		return cls._expand_with_label(epoch_secret, b"membership", b"", 32)

	def to_bytes(self) -> bytes:
		"""Serializes the full 9-secret schedule (288 bytes)."""
		return (
			self.joiner_secret
			+ self.epoch_secret
			+ self.sender_data_secret
			+ self.encryption_secret
			+ self.exporter_secret
			+ self.epoch_authenticator
			+ self.external_secret
			+ self.confirmation_key
			+ self.next_init_secret
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "KeySchedule":
		if len(data) != 288:
			raise ValueError(f"Invalid KeySchedule size: {len(data)} (expected 288)")
		return cls(
			joiner_secret=data[0:32],
			epoch_secret=data[32:64],
			sender_data_secret=data[64:96],
			encryption_secret=data[96:128],
			exporter_secret=data[128:160],
			epoch_authenticator=data[160:192],
			external_secret=data[192:224],
			confirmation_key=data[224:256],
			next_init_secret=data[256:288],
		)
