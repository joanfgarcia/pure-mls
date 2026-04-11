from unittest.mock import patch

import pytest

from pure_mls.group import EncryptedGroupSecrets, GroupContext, GroupInfo, GroupSecrets, MLSGroup, Welcome
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.keyschedule import PSK_TYPE_EXTERNAL, PreSharedKeyID
from pure_mls.tree import KeyPackage, RatchetTree


def test_join_with_psk_real_objects():
	"""
	Test E2E join workflow using real objects to avoid mock side-effects.
	"""
	# 1. Setup keys and PSK
	alice_sig = SignatureKey()
	alice_kem = KemKey()
	psk_id = PreSharedKeyID(psk_type=PSK_TYPE_EXTERNAL, psk_id=b"test_psk_id", psk_nonce=b"\x00" * 32)
	psk_value = b"very_secret_psk_value_32_bytes!!"[:32]

	# 2. Create Real GroupSecrets with PSK
	js = b"\x11" * 32
	gs = GroupSecrets(joiner_secret=js, psks=[psk_id])

	# 3. Create a valid Welcome structure
	from pure_mls.tls import ExtensionType
	tree = RatchetTree(num_leaves=1)
	tree_ext = [(ExtensionType.RATCHET_TREE, tree.to_bytes())]
	dummy_ctx = GroupContext(group_id=b"group1", epoch=1, tree_hash=b"\x00" * 32, confirmed_transcript_hash=b"\x00" * 32)
	gi = GroupInfo.build_and_sign(group_context=dummy_ctx, confirmation_tag=b"\x00" * 32, signer=0, sig_key=alice_sig, extensions=tree_ext)

	egi = b"\x00" * 12 + b"dummy_encrypted_group_info"
	egs = EncryptedGroupSecrets(new_member=b"\x00" * 32, kem_output=b"kem", ciphertext=b"ct")
	welcome = Welcome(cipher_suite=0x0001, encrypted_group_secrets=[egs], encrypted_group_info=egi)

	# 4. Patch ONLY the crypto operations
	with (
		patch("pure_mls.hpke.HPKE.open", return_value=gs.to_bytes()),
		patch("pure_mls.group.AESGCM.decrypt", return_value=gi.to_bytes() + b"\x00\x00"),
		patch("pure_mls.group.RatchetTree.from_bytes") as mock_rt_from_bytes,
		patch("pure_mls.group.hmac.compare_digest", return_value=True),
	):
		# Mock tree to return a leaf that matches Alice
		tree = RatchetTree(num_leaves=1)
		kp = KeyPackage.create(alice_kem.public_bytes(), alice_kem.public_bytes(), alice_sig.public_bytes(), b"id", alice_sig.sign)
		tree.set_leaf(0, kp.leaf_node)
		mock_rt_from_bytes.return_value = tree

		# Case A: Missing PSKs
		with pytest.raises(ValueError, match="Welcome message requires PSKs, but none were provided"):
			MLSGroup.join(welcome, alice_sig, alice_kem, psk_list=None)

		# Case B: Success with correct PSK
		with patch("pure_mls.group._compute_interim_transcript_hash") as mock_interim:
			mock_interim.return_value = b"new_interim_hash"
			group = MLSGroup.join(welcome, alice_sig, alice_kem, psk_list=[(psk_id, psk_value)])
			assert group is not None
			# Verify that the joiner_secret was correctly used in KeySchedule internally
			# We check the KeySchedule object inside the state
			assert group.state.key_schedule.joiner_secret == js


def test_group_secrets_psk_serialization():
	psk_id = PreSharedKeyID(psk_type=1, psk_id=b"id", psk_nonce=b"nonce")
	gs = GroupSecrets(joiner_secret=b"01234567890123456789012345678901", psks=[psk_id])

	data = gs.to_bytes()
	gs2 = GroupSecrets.from_bytes(data)

	assert gs2.joiner_secret == b"01234567890123456789012345678901"
	assert len(gs2.psks) == 1
	assert gs2.psks[0].psk_id == b"id"
	assert gs2.psks[0].psk_nonce == b"nonce"
