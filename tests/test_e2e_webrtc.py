import asyncio
import base64
import json
import os

import pytest
from aiortc import RTCPeerConnection, RTCSessionDescription

from pure_mls.group import MLSGroup, Welcome
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


class MockSignaler:
	"""In-memory signaling channel for exchanging SDP packets out of band."""

	def __init__(self):
		self.alice_to_bob = asyncio.Queue()
		self.bob_to_alice = asyncio.Queue()


@pytest.mark.asyncio
@pytest.mark.network
@pytest.mark.skipif(
	os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("PURE_MLS_FORCE_E2E") != "1",
	reason="Skipping WebRTC E2E in CI",
)
async def test_mls_webrtc_e2e():
	"""
	End-to-End P2P test using aiortc (WebRTC Data Channels).
	Simulates two Edge Agents establishing a zero-trust physical connection
	and bootstrapping Pure-MLS securely over the raw data stream.
	"""
	signaler = MockSignaler()
	test_done = asyncio.Future()

	async def alice_node():
		pc = None
		try:
			print("Alice: Initializing WebRTC")
			pc = RTCPeerConnection()
			channel = pc.createDataChannel("pure-mls-bus")

			sig = SignatureKey()
			kem = KemKey()
			alice_group = MLSGroup.create(b"webrtc-group", sig, kem)

			msg_queue = asyncio.Queue()

			@channel.on("open")
			def on_open():
				print("Alice: Data channel open!")

			@channel.on("message")
			def on_message(message):
				msg_queue.put_nowait(message)

			async def process_messages():
				nonlocal alice_group
				while True:
					message = await msg_queue.get()
					print(f"Alice: Received {message[:50]}...")
					msg = json.loads(message)
					if msg["type"] == "join_request":
						bob_kp = KeyPackage.from_bytes(base64.b64decode(msg["key_package"]))
						alice_next, welcome, _ = alice_group.add_member(bob_kp)

						enc, sealed_welcome = HPKE.seal(bob_kp.init_key_pub, welcome.to_bytes(), aad=b"webrtc_welcome", info=b"mls10-welcome")

						pub_msg = {
							"type": "sealed_welcome",
							"enc": base64.b64encode(enc).decode(),
							"ciphertext": base64.b64encode(sealed_welcome).decode(),
						}
						channel.send(json.dumps(pub_msg))
						alice_group = alice_next

					elif msg["type"] == "app_data":
						# P0-03: use MLS-compliant decrypt_application_message
						payload_bytes = base64.b64decode(msg["payload"])
						plaintext = alice_group.decrypt_application_message(payload_bytes)

						assert plaintext == b"Hello Alice, P2P Edge Node Bob securely online."
						print("Alice: Decrypted successfully!")
						test_done.set_result(True)

			asyncio.create_task(process_messages())

			print("Alice: Creating offer")
			offer = await pc.createOffer()
			await pc.setLocalDescription(offer)
			await signaler.alice_to_bob.put({"sdp": pc.localDescription.sdp, "type": pc.localDescription.type})

			print("Alice: Waiting for answer")
			answer_dict = await signaler.bob_to_alice.get()
			answer = RTCSessionDescription(sdp=answer_dict["sdp"], type=answer_dict["type"])
			await pc.setRemoteDescription(answer)
			print("Alice: Connection established, waiting for test_done")

			await test_done
			await pc.close()

		except Exception as e:
			print(f"Alice Error: {e}")
			if not test_done.done():
				test_done.set_exception(e)
			if pc is not None:
				await pc.close()

	async def bob_node():
		pc = None
		try:
			print("Bob: Initializing WebRTC")
			pc = RTCPeerConnection()

			sig = SignatureKey()
			kem = KemKey()
			kp = KeyPackage.create(
				encryption_key=kem.public_bytes(),
				init_key_pub=kem.public_bytes(),
				signature_key=sig.public_bytes(),
				identity=sig.public_bytes(),
				sign_fn=sig.sign,
			)

			@pc.on("datachannel")
			def on_datachannel(channel):
				print("Bob: Datachannel received from Alice")

				def _send_join():
					if getattr(channel, "_join_sent", False):
						return
					channel._join_sent = True
					print("Bob: Datachannel open, sending join request")
					req = {"type": "join_request", "key_package": base64.b64encode(kp.to_bytes()).decode()}
					channel.send(json.dumps(req))

				@channel.on("open")
				def on_open():
					_send_join()

				if channel.readyState == "open":
					_send_join()

				@channel.on("message")
				def on_message(message):
					print(f"Bob: Received {message[:50]}...")
					msg = json.loads(message)
					if msg["type"] == "sealed_welcome":
						enc = base64.b64decode(msg["enc"])
						ciphertext = base64.b64decode(msg["ciphertext"])

						pt_welcome = HPKE.open(kem, enc, ciphertext, aad=b"webrtc_welcome", info=b"mls10-welcome")
						welcome_info = Welcome.from_bytes(pt_welcome)

						bob_group = MLSGroup.join(welcome_info, sig, kem)

						# P0-03: use MLS-compliant encrypt_application_message
						reading = b"Hello Alice, P2P Edge Node Bob securely online."
						payload_bytes = bob_group.encrypt_application_message(reading)

						data_msg = {"type": "app_data", "payload": base64.b64encode(payload_bytes).decode()}
						channel.send(json.dumps(data_msg))

			print("Bob: Waiting for offer")
			offer_dict = await signaler.alice_to_bob.get()
			offer = RTCSessionDescription(sdp=offer_dict["sdp"], type=offer_dict["type"])
			await pc.setRemoteDescription(offer)

			print("Bob: Creating answer")
			answer = await pc.createAnswer()
			await pc.setLocalDescription(answer)
			await signaler.bob_to_alice.put({"sdp": pc.localDescription.sdp, "type": pc.localDescription.type})
			print("Bob: Answer sent, waiting for connection")

			await test_done
			await pc.close()

		except Exception as e:
			print(f"Bob Error: {e}")
			if not test_done.done():
				test_done.set_exception(e)
			if pc is not None:
				await pc.close()

	alice_task = asyncio.create_task(alice_node())
	bob_task = asyncio.create_task(bob_node())

	try:
		await asyncio.wait_for(test_done, timeout=10.0)
	finally:
		alice_task.cancel()
		bob_task.cancel()
		try:
			await alice_task
			await bob_task
		except asyncio.CancelledError:
			pass
