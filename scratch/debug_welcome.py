import json
from pathlib import Path


def _h(s: str) -> bytes:
	return bytes.fromhex(s) if s else b""


def _varint_decode(buf: bytes, offset: int) -> tuple[int, int]:
	first = buf[offset]
	offset += 1
	if (first & 0xC0) == 0:
		return first, offset
	elif (first & 0xC0) == 0x40:
		val = ((first & 0x3F) << 8) | buf[offset]
		return val, offset + 1
	elif (first & 0xC0) == 0x80:
		val = ((first & 0x3F) << 24) | (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
		return val, offset + 3
	raise ValueError("Too big")


def read_opaque_varint(buf: bytes, offset: int) -> tuple[bytes, int]:
	length, offset = _varint_decode(buf, offset)
	return buf[offset : offset + length], offset + length


def read_u16(buf: bytes, offset: int) -> tuple[int, int]:
	return int.from_bytes(buf[offset : offset + 2], "big"), offset + 2


# Load vectors
path = Path("tests/ietf_vectors/passive-client-welcome.json")
with open(path) as f:
	data = json.load(f)

for i, vec in enumerate(data):
	if vec["cipher_suite"] != 1:
		continue
	print(f"--- Vector {i} ---")
	data_bytes = _h(vec["welcome"])
	print(f"Total length: {len(data_bytes)}")
	print(f"First 64 bytes: {data_bytes[:64].hex(' ')}")

	offset = 0
	if data_bytes[:2] == b"\x00\x01" and data_bytes[2:4] == b"\x00\x03":
		print("MLSMessage header detected (4 bytes)")
		offset = 4

	version, offset = read_u16(data_bytes, offset)
	print(f"Welcome version: {version}")

	suite, offset = read_u16(data_bytes, offset)
	print(f"CipherSuite: {suite}")

	# Try RFC 9420 order: secrets<V> then EGI<V>
	try:
		egs_raw, offset = read_opaque_varint(data_bytes, offset)
		print(f"Secrets vector length: {len(egs_raw)}")

		egi, offset = read_opaque_varint(data_bytes, offset)
		print(f"EGI length: {len(egi)}")

		# Try to parse first secret
		if len(egs_raw) >= 32:
			new_member = egs_raw[:32]
			print(f"First new_member: {new_member.hex()}")
			egs_offset = 32
			kem, egs_offset = read_opaque_varint(egs_raw, egs_offset)
			print(f"First KEM output length: {len(kem)}")
			ct, egs_offset = read_opaque_varint(egs_raw, egs_offset)
			print(f"First ciphertext length: {len(ct)}")

	except Exception as e:
		print(f"Failed to parse as RFC 9420: {e}")

	break  # Just first one
