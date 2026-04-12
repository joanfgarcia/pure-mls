"""Test PSK secret derivation against IETF test vectors.

Vectors from: https://github.com/mlswg/mls-implementations/blob/main/test-vectors/psk_secret.json
These are the official RFC 9420 §8.4 interoperability test vectors.
"""

from pure_mls.keyschedule import PSK_TYPE_EXTERNAL, PreSharedKeyID, _psk_secret

# ── IETF Test Vectors (cipher_suite=1 = MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) ──

VECTORS_CS1 = [
	# 0 PSKs
	{
		"psks": [],
		"psk_secret": "0000000000000000000000000000000000000000000000000000000000000000",
	},
	# 1 PSK
	{
		"psks": [
			{
				"psk_id": "55c388e0e99fba6c1633d6b70c50ec3def72563aec7ce787847574bc27ed9d71",
				"psk": "e0a059e7da3660c691b5accb5342a0940f0ac7ea4ae4c886186249698d845860",
				"psk_nonce": "66b25bdc9086da6e266ed0828040d7a9547d20ddcfd2988d48113a10afb5a23d",
			}
		],
		"psk_secret": "aa6ee4e7ac86bec0a39c185ad88995e9b86eea9ecca113691090c53bcc86344c",
	},
	# 2 PSKs
	{
		"psks": [
			{
				"psk_id": "4e96d00ea2059b6c70d0e8777970e65677abee0c4b90e881c4cf7b4aaa8d9184",
				"psk": "62e3157cbb3799d0f54fb873e7f7e46257a01e9e4297413e769c4f0afeb1a206",
				"psk_nonce": "924a5371246476aca6a92eec7d295af3c9ed3f905aaeb97dc4748ac4cdc889fd",
			},
			{
				"psk_id": "8034d46a6150c7c4817f7584edf51006ec8432c55ae1de77d0ccd51c523ed97d",
				"psk": "27f5dd47bf87802cdfac24f1bfde71595a62ea8bc6a9ab335ba23c98d5fee267",
				"psk_nonce": "07ade6664316831d1ceddc1f7f8b26ff132f7130f4c6c6c51f07191d8f2a328e",
			},
		],
		"psk_secret": "e582f70f0b6a48dc9a50583895bc90012147e59bf7ba90b29673075fdb646ff2",
	},
	# 3 PSKs
	{
		"psks": [
			{
				"psk_id": "42aacc1afc76b1ada7a60114dd51aa740301ae8d4686f17560fffd29bc713e2f",
				"psk": "013bdae5ca37feb2e7cfa41a9fe09fc3f3d0784f32db2e7f0c065a0d4aefa963",
				"psk_nonce": "1be1e330144602b77c4205b139ca8b35e380a1f961efdbeb16a9516133c6dab9",
			},
			{
				"psk_id": "b4f3ad1afea819ec085d03d2f6c09ad5223df36ae3c04b4b309b3f86f0718708",
				"psk": "3781c20fec9b8df596b485aa0f7ba9107347a0fe14ff3d90a91379938ceb2682",
				"psk_nonce": "86ed1b2cccf4d67c588dc9b820eb701372215829bb5836f1d76e997030f48be6",
			},
			{
				"psk_id": "f8b94054d4ddd4040ac8e842b9a1cc88060ae0d0434b2543be14d0e9143d3b08",
				"psk": "6ff21d47faeb5ebe292ee8edd7a85e8650b8e0af483eff99c0c3e44fa3e459a1",
				"psk_nonce": "f3ae63a6abc2730c1620716bc47ce230da09da55839116d2ac7d9723167a36a9",
			},
		],
		"psk_secret": "f53ae4e49385c8655baba15eee503cc6a62898e459275a4f809aa07e9276dcdf",
	},
	# 4 PSKs
	{
		"psks": [
			{
				"psk_id": "b50a24a843c39597853e5369cbc0ff6e217dced2bcda45a4178f343ac6a6b869",
				"psk": "215f03b3262bf139a1f5194677a00b3532bc15ba6efb50e5aa2a680ed6e10438",
				"psk_nonce": "36522eb9210800490a7eb3e21ff9a32739e1d0859b9c1c57a510a9febaa48111",
			},
			{
				"psk_id": "abd00df4d4f2740b425c8d7bce4baa0cce09e04b06a0b35f007476ee515135f6",
				"psk": "7dba1c449de997096a524c2bec39ba0996987148793bacd8ff4aa99cdff74af8",
				"psk_nonce": "b304c6ade543ef54fe75875c21472d6b1585768517b3182c7e5b281423fac4cf",
			},
			{
				"psk_id": "74727932dee3778b1ffbf7d47ce1043839fbbc09c87953a1516a94bcd1f6a3ab",
				"psk": "3dbba7c5e1712adb2a90cfbb97e5689afa7d770a8c1125800ca1813c36c95ca6",
				"psk_nonce": "928189bc36e840898221218839832f98c3ca18b61557b76d72289d8a54107808",
			},
			{
				"psk_id": "1040d64243fe5e852805295c89acbea99d0785ac730c72308fa30d0def8e39b3",
				"psk": "2fd49e925216db08a9dc320fd9625e0bbdb6095da1f61b2e8ef33f1574b85366",
				"psk_nonce": "b23cc14eb856af892cfda85aa3f688d2e8ed2a1baf93214c333062a09dd3ee5b",
			},
		],
		"psk_secret": "57b3f32574edaa3d2f881e75107a6834da8b7217902c420e394ece92d2412fe3",
	},
	# 5 PSKs
	{
		"psks": [
			{
				"psk_id": "6d2f24a484ac5f87c48e60225c65147103dc807a237e5f8817aea47a99ba879c",
				"psk": "881a1d7c8da36746dea7cb562bf912cfdae244d6eb3880f9e0f1026548dc31aa",
				"psk_nonce": "e66f4bf1ec1e7c74af56dbacfaaa35086d94b02ec3c61a196ee6b3b33c8ff77e",
			},
			{
				"psk_id": "659f8743ae60d9912d159015d11fbf18f958cc34fee295ce89c8f8e767e04f8a",
				"psk": "5dae210592a907d51714fe5b177d3e442ea3070cd47a2e1908141c7d5409f99e",
				"psk_nonce": "b90e11dce8cc91ed8f66beba3916700be41ee147857cc049e7a83279452e1ed4",
			},
			{
				"psk_id": "04c16c0d7da83056e2789590241b5aba7bb2d7ccd7faa44cc71fa7b3e2032913",
				"psk": "47342226ce7f05631f4f2b7f41dfed85d93c2f1d414b1a2d756d6b6d4bdd6ff7",
				"psk_nonce": "db781f2fac3c9cf9af6518ceec69af91705479ce7875a1b800c966e84339b365",
			},
			{
				"psk_id": "a04635cc93eb1ee945062d76b828b1e5bb11c681c9d8358e9de8ef1cf81ef730",
				"psk": "87b11501959d512b844a45e282d57daa5140d4b4df2b76f0aec4f72f9899c042",
				"psk_nonce": "02451bbf8235edf8f05209b94e5c7fc21657b2ddf47ce3c7fcc415a821bedd23",
			},
			{
				"psk_id": "1a1a328df85a9d8d25bbd744ab17cafe108b6fb14ce9ce5c3ac08b3b9c4da5ea",
				"psk": "633e909efd2bbbbc16ef63ac1a0c3e69fe9941a7ab32310b541736097e23ffff",
				"psk_nonce": "f3149ba9c6de3acbc5c60d7692981ac8f94726c35bbbfe3a4333bb3efbfd2df5",
			},
		],
		"psk_secret": "2479d008ad482e524c53c1c60f34f75fa5e9df3666d3abff6e7fe43c3fd5d0e9",
	},
]


def _build_psk_list(vector: dict) -> list[tuple[PreSharedKeyID, bytes]]:
	"""Convert a test vector's PSK entries into (PreSharedKeyID, psk_value) tuples."""
	result = []
	for entry in vector["psks"]:
		psk_key_id = PreSharedKeyID(
			psk_type=PSK_TYPE_EXTERNAL,
			psk_id=bytes.fromhex(entry["psk_id"]),
			psk_nonce=bytes.fromhex(entry["psk_nonce"]),
		)
		psk_value = bytes.fromhex(entry["psk"])
		result.append((psk_key_id, psk_value))
	return result


class TestPskSecretIETF:
	"""Validate _psk_secret() against official IETF test vectors (cipher_suite=1)."""

	def test_empty_psk_list(self) -> None:
		"""0 PSKs → psk_secret = 0^32."""
		v = VECTORS_CS1[0]
		result = _psk_secret(None)
		assert result == bytes.fromhex(v["psk_secret"])

	def test_single_psk(self) -> None:
		"""1 PSK → matches IETF vector."""
		v = VECTORS_CS1[1]
		result = _psk_secret(_build_psk_list(v))
		assert result.hex() == v["psk_secret"], f"Expected {v['psk_secret']}, got {result.hex()}"

	def test_two_psks(self) -> None:
		"""2 PSKs → matches IETF vector."""
		v = VECTORS_CS1[2]
		result = _psk_secret(_build_psk_list(v))
		assert result.hex() == v["psk_secret"], f"Expected {v['psk_secret']}, got {result.hex()}"

	def test_three_psks(self) -> None:
		"""3 PSKs → matches IETF vector."""
		v = VECTORS_CS1[3]
		result = _psk_secret(_build_psk_list(v))
		assert result.hex() == v["psk_secret"], f"Expected {v['psk_secret']}, got {result.hex()}"

	def test_four_psks(self) -> None:
		"""4 PSKs → matches IETF vector."""
		v = VECTORS_CS1[4]
		result = _psk_secret(_build_psk_list(v))
		assert result.hex() == v["psk_secret"], f"Expected {v['psk_secret']}, got {result.hex()}"

	def test_five_psks(self) -> None:
		"""5 PSKs → matches IETF vector."""
		v = VECTORS_CS1[5]
		result = _psk_secret(_build_psk_list(v))
		assert result.hex() == v["psk_secret"], f"Expected {v['psk_secret']}, got {result.hex()}"
