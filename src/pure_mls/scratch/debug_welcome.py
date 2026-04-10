import json
from pathlib import Path

from pure_mls.tls import read_opaque, read_u16

VECTORS_PATH = Path("/home/joan/Documents/IA/pure-mls/tests/ietf_vectors/passive-client-welcome.json")


def debug():
	with open(VECTORS_PATH) as f:
		data = json.load(f)

	vec = data[0]
	welcome_hex = vec["welcome"]
	data_bin = bytes.fromhex(welcome_hex)

	print(f"Total welcome length: {len(data_bin)}")
	print(f"First 20 bytes: {data_bin[:20].hex()}")

	offset = 0
	v, offset = read_u16(data_bin, offset)
	print(f"Version: {v} (Offset: {offset})")

	cs, offset = read_u16(data_bin, offset)
	print(f"CipherSuite: {cs} (Offset: {offset})")

	try:
		# Assume Welcome starts with version(2B) then cipher_suite(2B) or just cipher_suite?
		# Based on 0001000300014098:
		#  0-1: 0001 (Msg v)
		#  2-3: 0003 (Msg type)
		#  4-5: 0001 (Welcome.CS? or Welcome.v?)
		#  6-7: 4098 (EGI len? or Welcome.CS?)

		# If EGI length is 4098 (152), let's try reading from 6.
		egi_raw, egs_offset = read_opaque(data_bin, 6)
		print(f"EGI length: {len(egi_raw)} (EGS starts at: {egs_offset})")

		# Now read EGS vector length
		egs_vector_raw, next_offset = read_opaque(data_bin, egs_offset)
		print(f"EGS Vector total bytes: {len(egs_vector_raw)}")

		# Try parsing first EGS assuming fixed 32-byte KPRef
		print(f"First 10 bytes of EGS raw: {egs_vector_raw[:10].hex()}")

		try:
			# Try fixed 32-byte
			kpref = egs_vector_raw[:32]
			print(f"Assumed fixed KPRef: {kpref.hex()}")

			# Next should be HPKECiphertext: kem_output<V>
			rem = egs_vector_raw[32:]
			kem_out, next_off = read_opaque(rem, 0)
			print(f"KEM Output length: {len(kem_out)} (Next offset: {next_off})")

			ct, final_off = read_opaque(rem, next_off)
			print(f"Ciphertext length: {len(ct)} (EGS total: {32 + final_off})")

		except Exception as e:
			print(f"Fixed-KPRef parse failed: {e}")

	except Exception as e:
		print(f"Error parsing Welcome: {e}")


if __name__ == "__main__":
	debug()
