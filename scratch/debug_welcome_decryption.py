import binascii
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pure_mls.group import GroupSecrets, Welcome, _egs_info
from pure_mls.hkdf import derive_secret, expand_with_label, hkdf_extract
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey


def _h(s):
	return binascii.unhexlify(s)


with open("tests/ietf_vectors/passive-client-welcome.json", "r") as f:
	vectors = json.load(f)

vec = vectors[0]
welcome_bytes = _h(vec["welcome"])
init_priv_bytes = _h(vec["init_priv"])

welcome = Welcome.from_bytes(welcome_bytes)
kem_key = KemKey.from_private_bytes(init_priv_bytes)

# 1. Open EGS
candidate = welcome.secrets[0]
info = _egs_info(welcome.encrypted_group_info)
gs_bytes = HPKE.open(kem_key, candidate.kem_output, candidate.ciphertext, info=info)
gs = GroupSecrets.from_bytes(gs_bytes)
print(f"Joiner secret: {gs.joiner_secret.hex()}")

# 2. Try derivations
labels_to_try = [
	("welcome", "key", "nonce"),
	("welcome", "welcome_key", "welcome_nonce"),
]

for label_s, label_k, label_n in labels_to_try:
	print(f"\nTrying labels: {label_s}, {label_k}, {label_n}")

	# Derivation A: Direct derive_secret
	ws_a = derive_secret(gs.joiner_secret, label_s)
	key_a = expand_with_label(ws_a, label_k, b"", 16)
	nonce_a = expand_with_label(ws_a, label_n, b"", 12)

	# Derivation B: Extract first
	psk_0 = b"\x00" * 32
	inter_b = hkdf_extract(gs.joiner_secret, psk_0)
	ws_b = derive_secret(inter_b, label_s)
	key_b = expand_with_label(ws_b, label_k, b"", 16)
	nonce_b = expand_with_label(ws_b, label_n, b"", 12)

	# Derivation C: Direct expand
	key_c = expand_with_label(gs.joiner_secret, label_k, b"", 16)
	nonce_c = expand_with_label(gs.joiner_secret, label_n, b"", 12)

	candidates = [
		("A", key_a, nonce_a),
		("B", key_b, nonce_b),
		("C", key_c, nonce_c),
	]

	for name, k, n in candidates:
		try:
			dec = AESGCM(k).decrypt(n, welcome.encrypted_group_info, b"")
			print(f"SUCCESS with derivation {name}!")
			exit(0)
		except Exception:
			pass
print("All derivations failed.")
