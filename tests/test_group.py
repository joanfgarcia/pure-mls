from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


def test_mls_group_lifecycle():
	# 1. Alice creates the group
	alice_sig = SignatureKey()
	alice_kem = KemKey()
	group_id = b"community-zero"

	alice_group = MLSGroup.create(group_id, alice_sig, alice_kem)

	assert alice_group.epoch_id == 0
	assert alice_group.my_index == 0
	assert alice_group.group_id == group_id

	# 2. Bob wants to join. He publishes a KeyPackage
	bob_sig = SignatureKey()
	bob_kem = KemKey()
	bob_kp = KeyPackage.create(
		encryption_key=bob_kem.public_bytes(),
		init_key_pub=bob_kem.public_bytes(),
		signature_key=bob_sig.public_bytes(),
		identity=bob_sig.public_bytes(),
		sign_fn=bob_sig.sign,
	)

	# 3. Alice adds Bob
	alice_group_next, welcome, update = alice_group.add_member(bob_kp)

	# Alice's state advanced
	assert alice_group_next.epoch_id == 1

	# 4. Bob processes the Welcome message
	bob_group = MLSGroup.join(welcome, my_sig_key=bob_sig, my_kem_key=bob_kem)

	# Bob should be on epoch 1
	assert bob_group.epoch_id == 1
	assert bob_group.state.tree.num_leaves == 2

	# Verify shared epoch via encrypt/decrypt roundtrip (RFC §9 SecretTree)
	msg = b"hello from alice"
	ct = alice_group_next.encrypt_application_message(msg)
	assert bob_group.decrypt_application_message(ct) == msg

	# 5. Assume Bob adds Charlie
	charlie_sig = SignatureKey()
	charlie_kem = KemKey()
	charlie_kp = KeyPackage.create(
		encryption_key=charlie_kem.public_bytes(),
		init_key_pub=charlie_kem.public_bytes(),
		signature_key=charlie_sig.public_bytes(),
		identity=charlie_sig.public_bytes(),
		sign_fn=charlie_sig.sign,
	)

	bob_group_next, charlie_welcome, charlie_update = bob_group.add_member(charlie_kp)

	# 6. Alice processes Bob's update
	alice_group_final = alice_group_next.process_update(charlie_update)

	assert alice_group_final.epoch_id == 2

	# Shared epoch 2: alice_final and bob_next can exchange messages
	msg2 = b"epoch-2 sync verified"
	ct2 = bob_group_next.encrypt_application_message(msg2)
	assert alice_group_final.decrypt_application_message(ct2) == msg2


def test_encrypt_decrypt_application_message():
	"""Regression: encrypt/decrypt_application_message uses SecretTree (RFC §9).
	Alice encrypts; Bob decrypts — two independent SecretTree instances, no forward-secrecy conflict.
	"""
	alice_sig = SignatureKey()
	alice_kem = KemKey()
	bob_sig = SignatureKey()
	bob_kem = KemKey()
	bob_kp = KeyPackage.create(
		encryption_key=bob_kem.public_bytes(),
		init_key_pub=bob_kem.public_bytes(),
		signature_key=bob_sig.public_bytes(),
		identity=bob_sig.public_bytes(),
		sign_fn=bob_sig.sign,
	)
	alice_group, welcome, _update = MLSGroup.create(b"g1", alice_sig, alice_kem).add_member(bob_kp)
	bob_group = MLSGroup.join(welcome, bob_sig, bob_kem)

	plaintext = b"sovereign payload"
	ct = alice_group.encrypt_application_message(plaintext)
	assert ct != plaintext
	recovered = bob_group.decrypt_application_message(ct)
	assert recovered == plaintext
