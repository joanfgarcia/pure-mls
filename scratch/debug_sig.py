import os
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from pure_mls.group import MLSGroup, GroupUpdate
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage

sig_alice = SignatureKey(private_key=ed25519.Ed25519PrivateKey.generate())
kem_alice = KemKey(private_key=x25519.X25519PrivateKey.generate())

sig_bob = SignatureKey(private_key=ed25519.Ed25519PrivateKey.generate())
kem_bob = KemKey(private_key=x25519.X25519PrivateKey.generate())

kp_bob = KeyPackage.create(
	encryption_key=kem_bob.public_bytes(),
	init_key_pub=KemKey().public_bytes(),
	signature_key=sig_bob.public_bytes(),
	identity=b"bob",
	sign_fn=sig_bob.sign,
)

alice = MLSGroup.create(b"test_group", sig_alice, kem_alice)
new_alice, welcome, commit = alice.add_member(kp_bob)

# Try applying the commit directly to alice (this should fail with out of order, or we can just test wrap/unwrap)
from pure_mls.group import MLSMessage

wrapped = MLSMessage.wrap_commit(commit)
unwrapped = wrapped.unwrap_commit()

print(f"Original signature: {commit.signature.hex()}")
print(f"Unwrapped signature: {unwrapped.signature.hex()}")
print(f"Original mem tag: {commit._membership_tag.hex()}")
print(f"Unwrapped mem tag: {unwrapped._membership_tag.hex()}")

# Now let's try to process it on a fresh member if we had one.
# Wait, Alice can't process it because she's at epoch 0.
# If she applies it, it should pass signature verification!
try:
	alice.apply_commit(unwrapped)
except Exception as e:
	print(f"Apply commit failed: {type(e).__name__}: {e}")
