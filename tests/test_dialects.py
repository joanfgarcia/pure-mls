"""Tests for the Adaptive Implementation Dialects codec plugin system."""

from typing import List, Tuple

from pure_mls.codecs import _REGISTRY, get_dialect, register_dialect
from pure_mls.group import EncryptedGroupSecrets, Welcome


def _not_auto_selected(data: bytes, forbidden: str) -> None:
	"""audit M9: parsing untrusted bytes without an explicit dialect must never
	auto-select a non-standard codec. Falling back to standard OR rejecting the
	mis-framed input are both acceptable; silently switching dialect is not."""
	try:
		assert Welcome.from_bytes(data).dialect != forbidden
	except ValueError:
		pass  # rejecting mis-framed input outright is fine


def test_dialect_selection_and_encoding() -> None:
	"""Verify Welcome serialization per dialect and explicit-only dialect selection."""
	# Create a mock EncryptedGroupSecrets
	egs = EncryptedGroupSecrets(
		new_member=b"member_ref_123",
		kem_output=b"kem_out_mock_123456789012345678",
		ciphertext=b"ciphertext_mock_data_hello_world",
	)

	# Welcome standard
	welcome_std = Welcome(
		cipher_suite=0x0001,
		encrypted_group_secrets=[egs],
		encrypted_group_info=b"group_info_mock",
		dialect="standard",
	)

	# Welcome cisco
	welcome_cisco = Welcome(
		cipher_suite=0x0001,
		encrypted_group_secrets=[egs],
		encrypted_group_info=b"group_info_mock",
		dialect="cisco",
	)

	# Welcome mlspp
	welcome_mlspp = Welcome(
		cipher_suite=0x0001,
		encrypted_group_secrets=[egs],
		encrypted_group_info=b"group_info_mock",
		dialect="mlspp",
	)

	# Serialize
	std_bytes = welcome_std.to_bytes()
	cisco_bytes = welcome_cisco.to_bytes()
	mlspp_bytes = welcome_mlspp.to_bytes()

	assert len(std_bytes) > 0
	assert len(cisco_bytes) > 0
	assert len(mlspp_bytes) > 0

	# Cisco uses prefix b"\xcc\x01"
	assert cisco_bytes.startswith(b"\xcc\x01")
	# mlspp uses prefix b"\xaa\x02"
	assert mlspp_bytes.startswith(b"\xaa\x02")
	# standard does not use dialect prefix, starts with cipher_suite b"\x00\x01"
	assert std_bytes.startswith(b"\x00\x01")

	# Parse back. audit M9: non-standard dialects require an explicit dialect= arg;
	# from_bytes must not auto-detect a dialect from untrusted leading bytes.
	parsed_std = Welcome.from_bytes(std_bytes)
	assert parsed_std.dialect == "standard"
	assert parsed_std.cipher_suite == 0x0001
	assert parsed_std.encrypted_group_info == b"group_info_mock"
	assert len(parsed_std.encrypted_group_secrets) == 1
	assert parsed_std.encrypted_group_secrets[0].new_member == b"member_ref_123"

	parsed_cisco = Welcome.from_bytes(cisco_bytes, dialect="cisco")
	assert parsed_cisco.dialect == "cisco"
	assert parsed_cisco.cipher_suite == 0x0001
	assert parsed_cisco.encrypted_group_info == b"group_info_mock"

	parsed_mlspp = Welcome.from_bytes(mlspp_bytes, dialect="mlspp")
	assert parsed_mlspp.dialect == "mlspp"
	assert parsed_mlspp.cipher_suite == 0x0001
	assert parsed_mlspp.encrypted_group_info == b"group_info_mock"

	# The untrusted cisco/mlspp headers must NOT trigger auto-selection of those codecs.
	_not_auto_selected(cisco_bytes, "cisco")
	_not_auto_selected(mlspp_bytes, "mlspp")


def test_custom_dialect_plugin() -> None:
	"""Verify that a custom third-party dialect plugin can be registered and used."""

	class CustomStrategy:
		@property
		def name(self) -> str:
			return "custom_test"

		def header(self) -> bytes:
			return b"\xff\xff"

		def welcome_label(self) -> bytes:
			return b"Custom welcome label"

		def encode_extensions(self, extensions: List[Tuple[int, bytes]]) -> bytes:
			return b""

		def decode_extensions(self, buf: bytes, offset: int) -> Tuple[List[Tuple[int, bytes]], int]:
			return [], offset

		def encode_vector(self, items: List[bytes]) -> bytes:
			body = b"".join(items)
			# Custom encoding: 1-byte length prefix (uint8)
			return bytes([len(body)]) + body

		def decode_vector(self, buf: bytes, offset: int) -> Tuple[List[bytes], int]:
			length = buf[offset]
			offset += 1
			return [buf[offset : offset + length]], offset + length

		def detect(self, data: bytes) -> bool:
			return data.startswith(b"\xff\xff")

	custom_strat = CustomStrategy()
	register_dialect(custom_strat)
	try:
		assert get_dialect("custom_test") is custom_strat

		egs = EncryptedGroupSecrets(
			new_member=b"custom_ref",
			kem_output=b"custom_kem",
			ciphertext=b"custom_cipher",
		)

		welcome = Welcome(
			cipher_suite=0x0001,
			encrypted_group_secrets=[egs],
			encrypted_group_info=b"custom_info",
			dialect="custom_test",
		)

		w_bytes = welcome.to_bytes()
		assert w_bytes.startswith(b"\xff\xff")

		parsed = Welcome.from_bytes(w_bytes, dialect="custom_test")
		assert parsed.dialect == "custom_test"
		assert parsed.encrypted_group_info == b"custom_info"
		assert len(parsed.encrypted_group_secrets) == 1
		assert parsed.encrypted_group_secrets[0].new_member == b"custom_ref"

		# audit M9: the untrusted 0xffff header must not auto-select the custom codec.
		_not_auto_selected(w_bytes, "custom_test")
	finally:
		# audit L10: don't leak the test dialect into the process-global registry
		_REGISTRY.pop("custom_test", None)
