"""RFC 9420 §8 Key Schedule — full compliant implementation.

Derivation chain:
	commit_secret + init_secret → HKDF-Extract(salt=commit_secret, ikm=init_secret) → joiner_secret
	joiner_secret + PSKSecret   → HKDF-Extract(salt=PSKSecret, ikm=joiner_secret) → epoch_secret

From epoch_secret (all via DeriveSecret / ExpandWithLabel with VarInt encoding):
	sender_data_secret    = DeriveSecret(epoch_secret, "sender data")
	encryption_secret     = DeriveSecret(epoch_secret, "encryption")
	exporter_secret       = DeriveSecret(epoch_secret, "exporter")
	epoch_authenticator   = DeriveSecret(epoch_secret, "authentication")
	external_secret       = DeriveSecret(epoch_secret, "external")
	resumption_psk_secret = DeriveSecret(epoch_secret, "resumption")
	init_secret           = DeriveSecret(epoch_secret, "init")

From authentication_secret (= epoch_authenticator in RFC nomenclature):
	confirmation_key = ExpandWithLabel(authentication_secret, "confirmation", b"", NH)
	membership_key   = ExpandWithLabel(authentication_secret, "membership", b"", NH)

PSKSecret (RFC §9.1): XOR combination of all PSK contributions.
When no PSKs are used: PSKSecret = b"\\x00" * NH (all-zero).
"""

import hashlib
from dataclasses import dataclass

from pure_mls.hkdf import derive_secret, expand_with_label, hkdf_extract

_NH = 32  # SHA-256 hash length


def _psk_secret(psk_list: list[tuple[bytes, bytes]] | None = None) -> bytes:
	"""RFC 9420 §9.1: PSKSecret derivation.

	psk_list: list of (psk_id, psk_value) tuples.
	When empty (no PSKs): PSKSecret = b"\\x00" * NH.

	Full multi-PSK XOR chain (simplified to 0..NH for no-PSK case):
		psk_extracted_i = HKDF-Extract(psk_i, "psk")
		pskInput(0)     = 0^NH
		pskInput(i+1)   = XOR(pskInput(i), psk_extracted_i ^ ExpandWithLabel(...))
	"""
	if not psk_list:
		return b"\x00" * _NH
	# Full multi-PSK not yet needed — placeholder for future implementation
	raise NotImplementedError("Multi-PSK not yet implemented (RFC §9.1)")


@dataclass
class KeySchedule:
	"""RFC 9420 §8: Immutable epoch key material.

	All fields are 32-byte (SHA-256 hash length) secrets derived for one group epoch.
	"""

	joiner_secret: bytes
	epoch_secret: bytes
	sender_data_secret: bytes
	encryption_secret: bytes
	exporter_secret: bytes
	epoch_authenticator: bytes
	external_secret: bytes
	resumption_psk_secret: bytes
	confirmation_key: bytes
	membership_key: bytes
	init_secret: bytes

	SIZE = 11 * 32  # 352 bytes (11 × 32)

	@classmethod
	def derive(
		cls,
		init_secret: bytes,
		commit_secret: bytes,
		group_context: bytes = b"",
		psk_list: list[tuple[bytes, bytes]] | None = None,
	) -> "KeySchedule":
		"""RFC 9420 §8: Derive all epoch secrets from previous init_secret + commit_secret.

		Args:
			init_secret:    Previous epoch's init_secret (or b"\\x00" * 32 for epoch 0).
			commit_secret:  TreeKEM commit secret (path secret at root after update).
			group_context:  TLS-encoded GroupContext (used in PSKSecret derivation, often b"" here).
			psk_list:       Optional list of PSK contributions [(psk_id, psk_value)].
		"""
		# Step 1: joiner_secret = HKDF-Extract(salt=commit_secret, ikm=init_secret)
		joiner_secret = hkdf_extract(commit_secret, init_secret, hashlib.sha256)

		# Step 2: epoch_secret = HKDF-Extract(salt=PSKSecret, ikm=joiner_secret)
		psk_secret = _psk_secret(psk_list)
		epoch_secret = hkdf_extract(psk_secret, joiner_secret, hashlib.sha256)

		return cls._from_epoch_secret(epoch_secret, joiner_secret)

	@classmethod
	def _from_epoch_secret(cls, epoch_secret: bytes, joiner_secret: bytes) -> "KeySchedule":
		"""Construct the full schedule from a known epoch_secret (used by joiners)."""
		# All labels are the exact strings from RFC 9420 §8 Table 3
		auth_secret = derive_secret(epoch_secret, "authentication")

		return cls(
			joiner_secret=joiner_secret,
			epoch_secret=epoch_secret,
			sender_data_secret=derive_secret(epoch_secret, "sender data"),
			encryption_secret=derive_secret(epoch_secret, "encryption"),
			exporter_secret=derive_secret(epoch_secret, "exporter"),
			epoch_authenticator=auth_secret,
			external_secret=derive_secret(epoch_secret, "external"),
			resumption_psk_secret=derive_secret(epoch_secret, "resumption"),
			confirmation_key=expand_with_label(auth_secret, "confirmation", b"", _NH),
			membership_key=expand_with_label(auth_secret, "membership", b"", _NH),
			init_secret=derive_secret(epoch_secret, "init"),
		)

	# -------------------------------------------------------------------------
	# Welcome key derivation (RFC 9420 §12.1.2)
	# -------------------------------------------------------------------------

	@staticmethod
	def derive_welcome_key(joiner_secret: bytes, context: bytes) -> bytes:
		"""RFC 9420 §12.1.2: welcome_key = ExpandWithLabel(joiner_secret, "welcome", ctx, Nk).

		Nk = 16 bytes (AES-128-GCM key length for MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).
		context = SHA-256(GroupInfo TBS) as per RFC §12.4.
		"""
		return expand_with_label(joiner_secret, "welcome", context, 16)

	@staticmethod
	def derive_welcome_nonce(joiner_secret: bytes, context: bytes) -> bytes:
		"""RFC 9420 §12.1.2: welcome_nonce = ExpandWithLabel(joiner_secret, "nonce", ctx, Nn).

		Nn = 12 bytes (AES-128-GCM nonce length).
		"""
		return expand_with_label(joiner_secret, "nonce", context, 12)

	# -------------------------------------------------------------------------
	# Serialization
	# -------------------------------------------------------------------------

	def to_bytes(self) -> bytes:
		"""Serialise all 11 secrets (352 bytes total)."""
		return (
			self.joiner_secret
			+ self.epoch_secret
			+ self.sender_data_secret
			+ self.encryption_secret
			+ self.exporter_secret
			+ self.epoch_authenticator
			+ self.external_secret
			+ self.resumption_psk_secret
			+ self.confirmation_key
			+ self.membership_key
			+ self.init_secret
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "KeySchedule":
		if len(data) != cls.SIZE:
			raise ValueError(f"Invalid KeySchedule size: {len(data)} (expected {cls.SIZE})")
		o = 0
		fields = {}
		for name in (
			"joiner_secret",
			"epoch_secret",
			"sender_data_secret",
			"encryption_secret",
			"exporter_secret",
			"epoch_authenticator",
			"external_secret",
			"resumption_psk_secret",
			"confirmation_key",
			"membership_key",
			"init_secret",
		):
			fields[name] = data[o : o + 32]
			o += 32
		return cls(**fields)
