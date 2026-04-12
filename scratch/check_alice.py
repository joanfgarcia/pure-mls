import binascii

# welcome-0 vector from tests/test_ietf_vectors.py (simplified import)
welcome_hex = ""
with open("tests/test_ietf_vectors.py", "r") as f:
	for line in f:
		if '"welcome": "' in line:
			welcome_hex = line.split('"')[3]
			break

data = binascii.unhexlify(welcome_hex)
# We know RatchetTree is in GroupInfo, but let's just look for the tree start.
# Alice: 01 01 20 ... (Leaf, HPKEKey 32)
# Let's find "01 01 20" or "01 01 00 20"
p1 = data.find(b"\x01\x01\x20")
p2 = data.find(b"\x01\x01\x00\x20")

if p1 != -1:
	print(f"Found Alice (VarInt style) at {p1}: {data[p1 : p1 + 10].hex()}")
if p2 != -1:
	print(f"Found Alice (uint16 style) at {p2}: {data[p2 : p2 + 10].hex()}")
