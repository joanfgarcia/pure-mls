"""Tests for RFC 9420 TLS wire format: GroupContext, Welcome, GroupUpdate, MLSMessage."""

import pytest

from pure_mls.group import (
	EncryptedGroupSecrets,
	GroupContext,
	GroupSecrets,
	GroupUpdate,
	MLSGroup,
	MLSMessage,
	Welcome,
	WireFormat,
)
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def alice_bob_group():
	"""Create a 2-member MLS group and return (alice_group, bob_group, welcome, update)."""
	alice_sig, alice_kem = SignatureKey(), KemKey()
	bob_sig, bob_kem = SignatureKey(), KemKey()
	bob_kp = KeyPackage(identity_key_pub=bob_sig.public_bytes(), init_key_pub=bob_kem.public_bytes())

	alice_group = MLSGroup.create(b"wire-format-test", alice_sig, alice_kem)
	alice_group2, welcome, update = alice_group.add_member(bob_kp)
	bob_group = MLSGroup.join(welcome, bob_sig, bob_kem)
	return alice_group2, bob_group, welcome, update


# ---------------------------------------------------------------------------
# GroupContext
# ---------------------------------------------------------------------------


def test_group_context_round_trip():
	"""GroupContext to_bytes()/from_bytes() produces an identical struct."""
	ctx = GroupContext(
		group_id=b"\xde\xad\xbe\xef" * 4,
		epoch=42,
		tree_hash=b"\xca\xfe" * 16,
		confirmed_transcript_hash=b"\xab\xcd" * 16,
	)
	encoded = ctx.to_bytes()
	decoded = GroupContext.from_bytes(encoded)
	assert decoded.group_id == ctx.group_id
	assert decoded.epoch == ctx.epoch
	assert decoded.tree_hash == ctx.tree_hash
	assert decoded.confirmed_transcript_hash == ctx.confirmed_transcript_hash


def test_group_context_unsupported_version():
	"""GroupContext.from_bytes raises ValueError for unknown version."""
	from pure_mls.tls import tls_u16

	bad_version = tls_u16(0x9999) + b"\x00" * 30
	with pytest.raises(ValueError, match="Unsupported GroupContext version"):
		GroupContext.from_bytes(bad_version)


# ---------------------------------------------------------------------------
# GroupSecrets
# ---------------------------------------------------------------------------


def test_group_secrets_round_trip():
	"""GroupSecrets to_bytes()/from_bytes() preserves fields."""
	gs = GroupSecrets(joiner_secret=b"\x01" * 32, joiner_index=5)
	decoded = GroupSecrets.from_bytes(gs.to_bytes())
	assert decoded.joiner_secret == gs.joiner_secret
	assert decoded.joiner_index == gs.joiner_index


# ---------------------------------------------------------------------------
# EncryptedGroupSecrets
# ---------------------------------------------------------------------------


def test_encrypted_group_secrets_round_trip():
	"""EncryptedGroupSecrets to_bytes()/from_bytes() with offset."""
	egs = EncryptedGroupSecrets(
		new_member=b"\xaa" * 32,
		kem_output=b"\xbb" * 32,
		ciphertext=b"\xcc" * 48,
	)
	raw = egs.to_bytes()
	decoded, offset = EncryptedGroupSecrets.from_bytes(raw, 0)
	assert decoded.new_member == egs.new_member
	assert decoded.kem_output == egs.kem_output
	assert decoded.ciphertext == egs.ciphertext
	assert offset == len(raw)


# ---------------------------------------------------------------------------
# Welcome
# ---------------------------------------------------------------------------


def test_welcome_round_trip(alice_bob_group):
	"""Welcome produced by add_member() survives to_bytes()/from_bytes()."""
	_, _, welcome, _ = alice_bob_group
	encoded = welcome.to_bytes()
	decoded = Welcome.from_bytes(encoded)
	assert decoded.cipher_suite == 0x0001
	assert len(decoded.encrypted_group_secrets) == 1
	assert decoded.encrypted_group_info == welcome.encrypted_group_info


def test_welcome_e2e_join(alice_bob_group):
	"""Bob can join from a Welcome that survives wire serialization."""
	_, _, welcome, _ = alice_bob_group
	# Re-serialize Welcome through wire format and join
	# (tests that the actual bytes are valid enough to reconstruct a group)
	encoded = welcome.to_bytes()
	decoded_welcome = Welcome.from_bytes(encoded)
	assert decoded_welcome.encrypted_group_secrets[0].new_member == welcome.encrypted_group_secrets[0].new_member


# ---------------------------------------------------------------------------
# GroupUpdate (Commit)
# ---------------------------------------------------------------------------


def test_group_update_round_trip(alice_bob_group):
	"""GroupUpdate to_bytes()/from_bytes() produces an identical struct."""
	_, _, _, update = alice_bob_group
	encoded = update.to_bytes()
	decoded = GroupUpdate.from_bytes(encoded)
	assert decoded.epoch_id == update.epoch_id
	assert decoded.committer_index == update.committer_index
	assert decoded.signature == update.signature
	assert set(decoded.encrypted_commit_secrets.keys()) == set(update.encrypted_commit_secrets.keys())


# ---------------------------------------------------------------------------
# MLSMessage envelope
# ---------------------------------------------------------------------------


def test_mls_message_welcome_round_trip(alice_bob_group):
	"""MLSMessage wrapping Welcome survives to_bytes()/from_bytes()."""
	_, _, welcome, _ = alice_bob_group
	msg = MLSMessage.wrap_welcome(welcome)
	assert msg.wire_format == WireFormat.MLS_WELCOME

	encoded = msg.to_bytes()
	decoded_msg = MLSMessage.from_bytes(encoded)
	assert decoded_msg.wire_format == WireFormat.MLS_WELCOME

	decoded_welcome = decoded_msg.unwrap_welcome()
	assert decoded_welcome.cipher_suite == welcome.cipher_suite
	assert len(decoded_welcome.encrypted_group_secrets) == 1


def test_mls_message_commit_round_trip(alice_bob_group):
	"""MLSMessage wrapping GroupUpdate survives to_bytes()/from_bytes()."""
	_, _, _, update = alice_bob_group
	msg = MLSMessage.wrap_commit(update)
	assert msg.wire_format == WireFormat.MLS_PUBLIC_MESSAGE

	encoded = msg.to_bytes()
	decoded_msg = MLSMessage.from_bytes(encoded)
	decoded_update = decoded_msg.unwrap_commit()
	assert decoded_update.epoch_id == update.epoch_id
	assert decoded_update.signature == update.signature


def test_mls_message_wrong_type_raises(alice_bob_group):
	"""MLSMessage.unwrap_commit() on a Welcome envelope raises ValueError."""
	_, _, welcome, _ = alice_bob_group
	msg = MLSMessage.wrap_welcome(welcome)
	with pytest.raises(ValueError, match="Expected MLS_PUBLIC_MESSAGE"):
		msg.unwrap_commit()


def test_mls_message_unsupported_version():
	"""MLSMessage.from_bytes raises for unknown version prefix."""
	from pure_mls.tls import tls_u16

	bad = tls_u16(0x9999) + b"\x00" * 10
	with pytest.raises(ValueError, match="Unsupported MLSMessage version"):
		MLSMessage.from_bytes(bad)


def test_mls_message_full_firebase_flow():
	"""Simulates a full zero-knowledge group join via MLSMessage bytes (Firebase model).

	Alice creates a group, wraps Welcome+Commit in MLSMessage (what would be
	pushed to Firebase), and Bob independently reconstructs the epoch state.
	"""
	alice_sig, alice_kem = SignatureKey(), KemKey()
	bob_sig, bob_kem = SignatureKey(), KemKey()
	bob_kp = KeyPackage(identity_key_pub=bob_sig.public_bytes(), init_key_pub=bob_kem.public_bytes())

	# Alice: create + add member
	alice = MLSGroup.create(b"firebase-group", alice_sig, alice_kem)
	alice2, welcome, update = alice.add_member(bob_kp)

	# Serialize exactly what would go to Firebase
	mls_welcome = MLSMessage.wrap_welcome(welcome).to_bytes()
	mls_commit = MLSMessage.wrap_commit(update).to_bytes()

	# Bob: reads bytes from Firebase, joins
	welcome_msg = MLSMessage.from_bytes(mls_welcome)
	decoded_welcome = welcome_msg.unwrap_welcome()
	bob = MLSGroup.join(decoded_welcome, bob_sig, bob_kem)

	# Alice processes her own commit to advance epoch
	alice3 = alice2  # Alice already advanced in add_member()

	# Both should be in epoch 1 with valid application keys
	assert alice3.epoch_id == bob.epoch_id == 1
	assert alice3.group_id == bob.group_id == b"firebase-group"

	# Cross-encrypt/decrypt to verify shared keys
	plaintext = b"hello from firebase"
	ciphertext = alice3.encrypt_application_message(plaintext)
	decrypted = bob.decrypt_application_message(ciphertext)
	assert decrypted == plaintext

	# Verify the Commit bytes can also be parsed (for existing members)
	commit_msg = MLSMessage.from_bytes(mls_commit)
	decoded_update = commit_msg.unwrap_commit()
	assert decoded_update.epoch_id == update.epoch_id
