import asyncio
import base64
import json
import os
import uuid

import aiomqtt
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pure_mls.group import MLSGroup, WelcomeInfo
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage

MQTT_BROKER = "localhost"
MQTT_PORT = 1883


@pytest.mark.asyncio
async def test_mls_mqtt_e2e():
	"""
	End-to-End IoT test using a public MQTT Broker.
	Alice and Bob establish a TreeKEM encrypted session over Public Pub/Sub.
	"""
	# Generate a random root topic to isolate this test execution from the public internet noise.
	test_run_id = str(uuid.uuid4())[:8]
	base_topic = f"redpill/pure-mls-test/{test_run_id}"

	topic_join = f"{base_topic}/join"
	topic_welcome = f"{base_topic}/welcome"
	topic_data = f"{base_topic}/data"

	# Future to sync test conclusion
	test_done = asyncio.Future()

	async def alice_node():
		try:
			async with aiomqtt.Client(hostname=MQTT_BROKER, port=MQTT_PORT) as client:
				# 1. Alice creates the Sovereign Group
				sig = SignatureKey()
				kem = KemKey()
				alice_group = MLSGroup.create(b"iot-group", sig, kem)

				# 2. Wait for someone to broadcast a KeyPackage on the join topic
				await client.subscribe(topic_join)
				await client.subscribe(topic_data)

				async for message in client.messages:
					topic = str(message.topic)
					payload = message.payload.decode()
					msg = json.loads(payload)

					if topic == topic_join and msg["type"] == "join_request":
						# Bob wants in.
						bob_kp_bytes = base64.b64decode(msg["key_package"])
						bob_kp = KeyPackage.from_bytes(bob_kp_bytes)

						# Apply TreeKEM to add Bob
						alice_next, welcome, update = alice_group.add_member(bob_kp)

						# HPKE Seal the Welcome specifically for Bob
						enc, sealed_welcome = HPKE.seal(bob_kp.init_key_pub, welcome.to_bytes(), b"mqtt_welcome")

						# Broadcast the sealed welcome
						pub_msg = {
							"type": "sealed_welcome",
							"enc": base64.b64encode(enc).decode(),
							"ciphertext": base64.b64encode(sealed_welcome).decode(),
						}
						await client.publish(topic_welcome, json.dumps(pub_msg))

						# Save the new group state
						alice_group = alice_next

						# Now wait for data

					elif topic == topic_data and msg["type"] == "app_data":
						# We got Bob's encrypted message!
						ct = base64.b64decode(msg["ct"])
						nonce = base64.b64decode(msg["nonce"])

						aes = AESGCM(alice_group.application_key)
						plaintext = aes.decrypt(nonce, ct, b"")

						assert plaintext == b"Hello Alice, IoT Sensor Node Bob is online and secure."
						test_done.set_result(True)
						break
		except Exception as e:
			if not test_done.done():
				test_done.set_exception(e)

	async def bob_node():
		try:
			async with aiomqtt.Client(hostname=MQTT_BROKER, port=MQTT_PORT) as client:
				# Bob initializes his identity
				sig = SignatureKey()
				kem = KemKey()
				kp = KeyPackage(identity_key_pub=sig.public_bytes(), init_key_pub=kem.public_bytes())

				# Bob subscribes to welcomes
				await client.subscribe(topic_welcome)

				# Bob blasts his KeyPackage requesting to join the cluster
				req = {"type": "join_request", "key_package": base64.b64encode(kp.to_bytes()).decode()}
				await client.publish(topic_join, json.dumps(req))

				async for message in client.messages:
					topic = str(message.topic)
					payload = message.payload.decode()
					msg = json.loads(payload)

					if topic == topic_welcome and msg["type"] == "sealed_welcome":
						# Found a welcome message! Unseal it.
						enc = base64.b64decode(msg["enc"])
						ciphertext = base64.b64decode(msg["ciphertext"])

						pt_welcome = HPKE.open(kem, enc, ciphertext, b"mqtt_welcome")
						welcome_info = WelcomeInfo.from_bytes(pt_welcome)

						# Reconstruct Sovereign Group in RAM
						bob_group = MLSGroup.join(welcome_info, 2, sig, kem)
						app_key = bob_group.application_key

						# We are in! We share an opaque cryptographic layer.
						# Let's send an encrypted reading.
						aes = AESGCM(app_key)
						nonce = os.urandom(12)
						reading = b"Hello Alice, IoT Sensor Node Bob is online and secure."
						ct = aes.encrypt(nonce, reading, b"")

						data_msg = {"type": "app_data", "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}
						await client.publish(topic_data, json.dumps(data_msg))
						break
		except Exception as e:
			if not test_done.done():
				test_done.set_exception(e)

	# Run Alice and Bob concurrently
	alice_task = asyncio.create_task(alice_node())
	bob_task = asyncio.create_task(bob_node())

	# Wait for the future to complete (or fail) within a timeout of 10 seconds
	await asyncio.wait_for(test_done, timeout=10.0)

	alice_task.cancel()
	bob_task.cancel()

	try:
		await alice_task
		await bob_task
	except asyncio.CancelledError:
		pass
