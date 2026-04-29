import os
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from pure_mls.group import MLSGroup, GroupUpdate, MLSMessage
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage

sig_alice = SignatureKey(private_key=ed25519.Ed25519PrivateKey.generate())
kem_alice = KemKey(private_key=x25519.X25519PrivateKey.generate())

sig_bob = SignatureKey(private_key=ed25519.Ed25519PrivateKey.generate())
kem_bob = KemKey(private_key=x25519.X25519PrivateKey.generate())

sig_charlie = SignatureKey(private_key=ed25519.Ed25519PrivateKey.generate())
kem_charlie = KemKey(private_key=x25519.X25519PrivateKey.generate())

kp_bob = KeyPackage.create(
	encryption_key=kem_bob.public_bytes(),
	init_key_pub=kem_bob.public_bytes(),
	signature_key=sig_bob.public_bytes(),
	identity=b"bob",
	sign_fn=sig_bob.sign,
)

kp_charlie = KeyPackage.create(
	encryption_key=kem_charlie.public_bytes(),
	init_key_pub=kem_charlie.public_bytes(),
	signature_key=sig_charlie.public_bytes(),
	identity=b"charlie",
	sign_fn=sig_charlie.sign,
)

print("Alice creates group")
alice = MLSGroup.create(b"test_group", sig_alice, kem_alice)

print("Alice adds Bob")
alice, welcome_bob, commit_bob = alice.add_member(kp_bob)

print("Bob joins")
bob = MLSGroup.join(welcome_bob.to_bytes(), sig_bob, kem_bob)
bob_bytes = bob.to_bytes()
bob = MLSGroup.from_bytes(bob_bytes)

print("Alice adds Charlie")
alice_bytes = alice.to_bytes()
alice = MLSGroup.from_bytes(alice_bytes)
alice, welcome_charlie, commit_charlie = alice.add_member(kp_charlie)

print("Charlie joins")
charlie = MLSGroup.join(welcome_charlie.to_bytes(), sig_charlie, kem_charlie)

print("Bob applies Alice's commit adding Charlie")
wrapped_commit_charlie = MLSMessage.wrap_commit(commit_charlie).to_bytes()

# Bob unwraps and applies
msg = MLSMessage.from_bytes(wrapped_commit_charlie)
unwrapped_commit = msg.unwrap_commit()

try:
	bob = bob.apply_commit(unwrapped_commit)
	print("SUCCESS: Bob applied commit!")
except Exception as e:
	import traceback

	traceback.print_exc()
