# Zero-Trust Diagnostic for welcome-0
import hmac
import json
from pathlib import Path

from pure_mls.group import GroupInfo, GroupSecrets, Welcome, _egs_info
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import LeafNode, RatchetTree


def _h(s):
	return bytes.fromhex(s) if s else b""


# 1. Load All Vectors
vdir = Path("tests/ietf_vectors")
with open(vdir / "passive-client-welcome.json") as f:
	data = json.load(f)

for idx, vec in enumerate(data):
	if vec["cipher_suite"] != 1:
		continue

	print(f"\n>>> Testing Vector {idx}: {vec.get('description', 'welcome')}")

	try:
		welcome_bytes = _h(vec["welcome"])
		init_priv_bytes = _h(vec["init_priv"])
		sig_priv_bytes = _h(vec["signature_priv"])

		# 2. Derive Keys
		sig_key = SignatureKey.from_private_bytes(sig_priv_bytes)
		kem_key = KemKey.from_private_bytes(init_priv_bytes)
		my_sig_pub = sig_key.public_bytes()

		# 3. Parse Welcome
		welcome = Welcome.from_bytes(welcome_bytes)

		# 4. Decrypt GroupSecrets
		gs_bytes = None
		for candidate in welcome.secrets:
			try:
				from pure_mls.hpke import HPKE

				gs_bytes = HPKE.open(kem_key, candidate.kem_output, candidate.ciphertext, info=_egs_info(welcome.encrypted_group_info))
				break
			except Exception:
				continue

		if not gs_bytes:
			print("  [-] FAILED: Could not decrypt GroupSecrets")
			continue

		gs = GroupSecrets.from_bytes(gs_bytes)

		# 5. Decrypt GroupInfo
		from cryptography.hazmat.primitives.ciphers.aead import AESGCM

		from pure_mls.keyschedule import KeySchedule, _psk_secret

		# Resolve PSKs (simplifying: vector 0-N often have no external PSKs in GS)
		# Real impl should resolve them.
		psk_secret = _psk_secret([])
		welcome_key = KeySchedule.derive_welcome_key(gs.joiner_secret, psk_secret)
		welcome_nonce = KeySchedule.derive_welcome_nonce(gs.joiner_secret, psk_secret)

		gi_bytes = AESGCM(welcome_key).decrypt(welcome_nonce, welcome.encrypted_group_info, b"")

		# 6. Parse GroupInfo & Search Identity
		gi = GroupInfo.from_bytes(gi_bytes)
		tree = None
		from pure_mls.extensions import ExtensionType

		for et, ed in gi.extensions:
			if et == ExtensionType.RATCHET_TREE:
				tree = RatchetTree.from_bytes(ed)
				break

		if not tree:
			print("  [-] FAILED: No ratchet_tree in GroupInfo")
			continue

		my_index = None
		for i, node in enumerate(tree.nodes):
			if i % 2 == 0 and isinstance(node, LeafNode):
				if hmac.compare_digest(node.signature_key, my_sig_pub):
					my_index = i
					break

		if my_index is not None:
			print(f"  [+] SUCCESS: Found myself at index {my_index}")
			# 7. Verify Signature
			committer = tree.get_node(gi.signer)
			gi.verify(committer.signature_key)
			print("  [+] SUCCESS: Signature verified!")
		else:
			print("  [-] FAILED: My leaf NOT found in tree!")
			# Check if Alice's pub key in tree matches ANY derived pub key?
			# Leaf 0 sig pub: tree.nodes[0].signature_key.hex()
			# Derived sig pub: my_sig_pub.hex()
	except Exception as e:
		print(f"  [!] ERROR: {e}")
