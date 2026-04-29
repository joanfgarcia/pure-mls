import asyncio

import pytest
import pytest_asyncio
from amqtt.broker import Broker  # type: ignore[import-untyped]


@pytest.fixture(scope="function")
def mqtt_broker_config():
	"""Returns the standard configuration for the test broker."""
	return {
		"listeners": {
			"default": {
				"type": "tcp",
				"bind": "127.0.0.1:1883",
			}
		},
		"sys_interval": 10,
		"auth": {
			"allow-anonymous": True,
		},
	}


@pytest_asyncio.fixture(scope="function")
async def mqtt_broker(mqtt_broker_config):
	"""
	Starts an amqtt broker for the duration of the test session.
	Ensures tests have a reliable transport without external dependencies.
	"""
	broker = Broker(mqtt_broker_config)
	await broker.start()

	# Small delay to ensure the listener is ready
	await asyncio.sleep(0.5)

	yield broker

	await broker.shutdown()
