import base64
import json

import pytest
import websockets

from pure_mls.group import MLSGroup, Welcome
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


class BroadcastServer:
	def __init__(self, host="127.0.0.1", port=8765):
		self.host = host
		self.port = port
		self.clients = set()
		self.server = None

	async def handler(self, websocket):
		self.clients.add(websocket)
		try:
			async for message in websocket:
				for client in self.clients:
					if client != websocket:
						await client.send(message)
		finally:
			self.clients.remove(websocket)

	async def start(self):
		self.server = await websockets.serve(self.handler, self.host, self.port)

	async def stop(self):
		if self.server:
			self.server.close()
			await self.server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.skipif(
	os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("PURE_MLS_FORCE_E2E") != "1",
	reason="Skipping WebSockets E2E in CI",
)
async def test_mls_websockets_e2e():
	"""
	End-to-End WebSocket Test bridging Pure-MLS.
	Alice creates Group -> Generates Welcome -> Seals Welcome with HPKE -> Sends via WS
	-> Bob receives -> Unseals Welcome -> Joins Group -> Chat Message Exchanged.
	"""
	server = BroadcastServer(port=8768)
	await server.start()

	try:
		uri = "ws://127.0.0.1:8768"
		async with websockets.connect(uri) as alice_ws, websockets.connect(uri) as bob_ws:
			# Alice -> Creator
			alice_sig = SignatureKey()
			alice_kem = KemKey()
			alice_group = MLSGroup.create(b"ws-group", alice_sig, alice_kem)

			# Bob -> Joiner
			bob_sig = SignatureKey()
			bob_kem = KemKey()
			bob_kp = KeyPackage.create(
				encryption_key=bob_kem.public_bytes(),
				init_key_pub=bob_kem.public_bytes(),
				signature_key=bob_sig.public_bytes(),
				identity=bob_sig.public_bytes(),
				sign_fn=bob_sig.sign,
			)

			# Alice adds Bob
			alice_next, welcome, update = alice_group.add_member(bob_kp)

			# E2E Network Send: Alice seals the Welcome using HPKE to Bob's init_key_pub
			sealed_enc, sealed_welcome = HPKE.seal(bob_kp.init_key_pub, welcome.to_bytes(), aad=b"welcome_v1", info=b"mls10-welcome")

			msg = {"type": "sealed_welcome", "enc": base64.b64encode(sealed_enc).decode(), "ciphertext": base64.b64encode(sealed_welcome).decode()}
			await alice_ws.send(json.dumps(msg))

			# Bob receives
			raw_msg = await bob_ws.recv()
			recv_msg = json.loads(raw_msg)

			assert recv_msg["type"] == "sealed_welcome"

			# Bob unseals with his KEM Private Key
			enc = base64.b64decode(recv_msg["enc"])
			ciphertext = base64.b64decode(recv_msg["ciphertext"])

			plaintext_welcome = HPKE.open(bob_kem, enc, ciphertext, aad=b"welcome_v1", info=b"mls10-welcome")
			received_welcome = Welcome.from_bytes(plaintext_welcome)

			# Bob Joins!
			bob_group = MLSGroup.join(received_welcome, bob_sig, bob_kem)

			# P0-03 fix: use RFC §9 SecretTree API — no raw AESGCM, no application_key
			pt = b"Hello Bob, welcome to the Sovereign Vault. TreeKEM established."
			ct_bytes = alice_next.encrypt_application_message(pt)

			await alice_ws.send(json.dumps({"type": "app_message", "payload": base64.b64encode(ct_bytes).decode()}))

			chat_msg = json.loads(await bob_ws.recv())
			assert chat_msg["type"] == "app_message"

			decrypted = bob_group.decrypt_application_message(base64.b64decode(chat_msg["payload"]))
			assert decrypted == pt

	finally:
		await server.stop()
