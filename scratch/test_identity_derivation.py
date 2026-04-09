from pure_mls.hkdf import expand_with_label
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def derive_sig_key(seed: bytes):
    # RFC 9420 §12.1.1: DeriveKeyPair(seed, "SignatureKey", "")
    # The pure_mls.hkdf.expand_with_label expects label as string.
    derived_seed = expand_with_label(seed, "SignatureKey", b"", 32)
    priv = Ed25519PrivateKey.from_private_bytes(derived_seed)
    return priv.public_key().public_bytes_raw()

seed = bytes.fromhex("08c760e174e466ec33ff13eb72eadd44e1b7842bc5b25cfe1ebe755733f7b26c")
expected_pub = "9cf32f91d3c021765b082877a4807b69fff7e795241e423d82920618c20fbf1d"

derived_pub = derive_sig_key(seed)
print(f"Derived Pub:  {derived_pub.hex()}")
print(f"Expected Pub: {expected_pub}")
print(f"MATCH: {derived_pub.hex() == expected_pub}")
