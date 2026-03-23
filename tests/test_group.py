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
	assert alice_group.application_key is not None
	orig_app_key = alice_group.application_key

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
	assert alice_group_next.application_key != orig_app_key

	# 4. Bob processes the Welcome message
	bob_group = MLSGroup.join(welcome, my_sig_key=bob_sig, my_kem_key=bob_kem)

	# Bob should be on epoch 1, and his keys should match Alice's perfectly
	assert bob_group.epoch_id == 1
	assert bob_group.application_key == alice_group_next.application_key
	assert bob_group.state.tree.num_leaves == 2

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
	assert alice_group_final.application_key == bob_group_next.application_key
