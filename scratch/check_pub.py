import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

priv_hex = sys.argv[1]
priv_bytes = bytes.fromhex(priv_hex)
if len(priv_bytes) == 64:
	priv_bytes = priv_bytes[:32]
priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
pub = priv.public_key()
print(pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex())
