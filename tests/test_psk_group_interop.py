from unittest.mock import patch

import pytest

from pure_mls.group import EncryptedGroupSecrets, GroupSecrets, MLSGroup, Welcome
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.keyschedule import PSK_TYPE_EXTERNAL, PreSharedKeyID


def test_join_requires_psk_when_welcome_demands_it():
	"""audit H5: the PSK-required guard must fire when GroupSecrets lists PSKs but
	none are provided.

	Only the HPKE transport is mocked (so we reach the guard); NO security check is
	stubbed. The previous version patched hmac.compare_digest -> True and asserted a
	"success" case, which disabled confirmation_tag/membership_tag verification and
	proved nothing. Functional PSK correctness is covered by
	test_psk_injection_multi_key and the psk_secret KATs in test_psk_vectors.py.
	"""
	alice_sig = SignatureKey()
	alice_kem = KemKey()
	psk_id = PreSharedKeyID(psk_type=PSK_TYPE_EXTERNAL, psk_id=b"test_psk_id", psk_nonce=b"\x00" * 32)

	gs = GroupSecrets(joiner_secret=b"\x11" * 32, psks=[psk_id])
	egi = b"\x00" * 12 + b"dummy_encrypted_group_info"
	egs = EncryptedGroupSecrets(new_member=b"\x00" * 32, kem_output=b"kem", ciphertext=b"ct")
	welcome = Welcome(cipher_suite=0x0001, encrypted_group_secrets=[egs], encrypted_group_info=egi)

	# The guard fires before any GroupInfo decryption / tag check, so only HPKE.open
	# needs mocking to deliver the GroupSecrets that declare a required PSK.
	with patch("pure_mls.hpke.HPKE.open", return_value=gs.to_bytes()):
		with pytest.raises(ValueError, match="requires PSKs"):
			MLSGroup.join(welcome, alice_sig, alice_kem, psk_list=None)


def test_group_secrets_psk_serialization():
	psk_id = PreSharedKeyID(psk_type=1, psk_id=b"id", psk_nonce=b"nonce")
	gs = GroupSecrets(joiner_secret=b"01234567890123456789012345678901", psks=[psk_id])

	data = gs.to_bytes()
	gs2 = GroupSecrets.from_bytes(data)

	assert gs2.joiner_secret == b"01234567890123456789012345678901"
	assert len(gs2.psks) == 1
	assert gs2.psks[0].psk_id == b"id"
	assert gs2.psks[0].psk_nonce == b"nonce"
