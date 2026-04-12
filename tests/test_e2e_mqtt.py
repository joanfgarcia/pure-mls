import asyncio
import base64
import json
import socket
import uuid

import aiomqtt
import pytest

from pure_mls.group import MLSGroup, Welcome
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage

# ---------------------------------------------------------------------------
# Sovereign Audit Protocol: Dual-Mode Testing
# ---------------------------------------------------------------------------
# To ensure Engineering Grade reliability, this test suite supports two modes:
# 1. LIVE MODE: Connects to a real MQTT broker (e.g., Mosquitto in Docker).
#    Activated automatically if port 1883 is responsive on localhost.
# 2. SKIP MODE: Skips the test if no broker is detected.
#    Default for CI to prevent network-induced deadlocks/hangs.
# ---------------------------------------------------------------------------

MQTT_BROKER = "localhost"
MQTT_PORT = 1883


def is_broker_online(host: str, port: int) -> bool:
	"""Pre-flight check: is there a real broker listening?"""
	try:
		with socket.create_connection((host, port), timeout=0.1):
			return True
	except (OSError, ConnectionRefusedError):
		return False


@pytest.mark.asyncio
@pytest.mark.network
@pytest.mark.skipif(not is_broker_online(MQTT_BROKER, MQTT_PORT), reason="No MQTT broker found on port 1883 (Local Audit mode only)")
async def test_mls_mqtt_e2e():
	"""
	End-to-End IoT test validating TreeKEM over a real MQTT transport.

	AUDIT NOTE: This test validates the full cryptographic lifecycle:
	KeyPackage -> Welcome (HPKE) -> Group Join -> App Data (SecretTree).
	In CI, this test is skipped to ensure determinism. Auditors should
	start Mosquitto on port 1883 to enable this validation.
	"""
	test_run_id = str(uuid.uuid4())[:8]
	base_topic = f"redpill/pure-mls-test/{test_run_id}"

	topic_join = f"{base_topic}/join"
	topic_welcome = f"{base_topic}/welcome"
	topic_data = f"{base_topic}/data"

	test_done = asyncio.Future()

	async def alice_node():
		try:
			async with aiomqtt.Client(hostname=MQTT_BROKER, port=MQTT_PORT) as client:
				sig = SignatureKey()
				kem = KemKey()
				alice_group = MLSGroup.create(b"iot-group", sig, kem)

				await client.subscribe(topic_join)
				await client.subscribe(topic_data)

				async for message in client.messages:
					topic = str(message.topic)
					payload = message.payload.decode()
					msg = json.loads(payload)

					if topic == topic_join and msg["type"] == "join_request":
						bob_kp = KeyPackage.from_bytes(base64.b64decode(msg["key_package"]))
						alice_next, welcome, _ = alice_group.add_member(bob_kp)
						enc, sealed_welcome = HPKE.seal(bob_kp.init_key_pub, welcome.to_bytes(), aad=b"mqtt_welcome", info=b"mls10-welcome")

						pub_msg = {
							"type": "sealed_welcome",
							"enc": base64.b64encode(enc).decode(),
							"ciphertext": base64.b64encode(sealed_welcome).decode(),
						}
						await client.publish(topic_welcome, json.dumps(pub_msg))
						alice_group = alice_next

					elif topic == topic_data and msg["type"] == "app_data":
						payload_bytes = base64.b64decode(msg["payload"])
						plaintext = alice_group.decrypt_application_message(payload_bytes)
						assert plaintext == b'{"temp": 24.5, "sensor": "bob_01"}'
						test_done.set_result(True)
						break
		except Exception as e:
			if not test_done.done():
				test_done.set_exception(e)

	async def bob_node():
		try:
			# Give Alice a moment to subscribe
			await asyncio.sleep(0.2)
			async with aiomqtt.Client(hostname=MQTT_BROKER, port=MQTT_PORT) as client:
				sig = SignatureKey()
				kem = KemKey()
				kp = KeyPackage.create(
					encryption_key=kem.public_bytes(),
					init_key_pub=kem.public_bytes(),
					signature_key=sig.public_bytes(),
					identity=sig.public_bytes(),
					sign_fn=sig.sign,
				)

				await client.subscribe(topic_welcome)
				req = {"type": "join_request", "key_package": base64.b64encode(kp.to_bytes()).decode()}
				await client.publish(topic_join, json.dumps(req))

				async for message in client.messages:
					topic = str(message.topic)
					payload = message.payload.decode()
					msg = json.loads(payload)

					if topic == topic_welcome and msg["type"] == "sealed_welcome":
						enc = base64.b64decode(msg["enc"])
						ciphertext = base64.b64decode(msg["ciphertext"])
						pt_welcome = HPKE.open(kem, enc, ciphertext, aad=b"mqtt_welcome", info=b"mls10-welcome")
						welcome_info = Welcome.from_bytes(pt_welcome)

						bob_group = MLSGroup.join(welcome_info, sig, kem)
						reading = b'{"temp": 24.5, "sensor": "bob_01"}'
						payload_bytes = bob_group.encrypt_application_message(reading)

						data_msg = {"type": "app_data", "payload": base64.b64encode(payload_bytes).decode()}
						await client.publish(topic_data, json.dumps(data_msg))
						break
		except Exception as e:
			if not test_done.done():
				test_done.set_exception(e)

	alice_task = asyncio.create_task(alice_node())
	bob_task = asyncio.create_task(bob_node())

	await asyncio.wait_for(test_done, timeout=10.0)

	alice_task.cancel()
	bob_task.cancel()
	try:
		await alice_task
		await bob_task
	except asyncio.CancelledError:
		pass
