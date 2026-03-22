import asyncio
import os
import sys
from typing import Dict

import grpc
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "protos"))
import mls_pb2
import mls_pb2_grpc

from pure_mls.group import MLSGroup, Welcome
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


class MLSSwarmServicer(mls_pb2_grpc.MLSSwarmServicer):
	def __init__(self):
		self.join_requests: Dict[str, bytes] = {}
		self.welcomes_queues: Dict[str, asyncio.Queue] = {}

	async def JoinSwarm(self, request, context):
		self.join_requests[request.identity] = request.key_package
		if request.identity not in self.welcomes_queues:
			self.welcomes_queues[request.identity] = asyncio.Queue()
		return mls_pb2.JoinResponse(success=True)

	async def DeliverWelcome(self, request, context):
		if request.target_identity in self.welcomes_queues:
			await self.welcomes_queues[request.target_identity].put(request)
		return mls_pb2.Ack()

	async def ListenWelcomes(self, request, context):
		if request.identity not in self.welcomes_queues:
			self.welcomes_queues[request.identity] = asyncio.Queue()

		queue = self.welcomes_queues[request.identity]
		while not context.done():
			try:
				welcome_msg = await asyncio.wait_for(queue.get(), timeout=1.0)
				yield welcome_msg
			except asyncio.TimeoutError:
				continue
			except asyncio.CancelledError:
				break


@pytest.mark.asyncio
async def test_mls_grpc_e2e():
	"""
	End-to-End backend test using gRPC.
	Applies the Zero-Trust Architecture:
	The gRPC server routes traffic but CANNOT read the TreeKEM epochs.
	"""
	# 1. Start gRPC Server
	server = grpc.aio.server()
	servicer = MLSSwarmServicer()
	mls_pb2_grpc.add_MLSSwarmServicer_to_server(servicer, server)
	server.add_insecure_port("[::]:50051")
	await server.start()

	try:
		channel = grpc.aio.insecure_channel("localhost:50051")
		stub = mls_pb2_grpc.MLSSwarmStub(channel)

		# 2. Bob announces himself to the Swarm Directory
		bob_sig = SignatureKey()
		bob_kem = KemKey()
		bob_kp = KeyPackage(identity_key_pub=bob_sig.public_bytes(), init_key_pub=bob_kem.public_bytes())

		await stub.JoinSwarm(mls_pb2.JoinRequest(identity="bob", key_package=bob_kp.to_bytes()))

		# 3. Alice (Admin) reads Bob's request and admits him
		# In a real Swarm, Alice would use a FetchJoinRequests RPC.
		assert "bob" in servicer.join_requests
		bob_req_bytes = servicer.join_requests["bob"]
		bob_parsed_kp = KeyPackage.from_bytes(bob_req_bytes)

		alice_sig = SignatureKey()
		alice_kem = KemKey()
		alice_group = MLSGroup.create(b"grpc-swarm", alice_sig, alice_kem)

		alice_next, welcome, update = alice_group.add_member(bob_parsed_kp)

		# Alice HPKE seals the Welcome for Bob using his public key
		enc, sealed_welcome = HPKE.seal(bob_parsed_kp.init_key_pub, welcome.to_bytes(), aad=b"grpc_welcome", info=b"mls10-welcome")

		# Alice pushes the sealed Welcome to the Swarm
		await stub.DeliverWelcome(mls_pb2.WelcomeMessage(target_identity="bob", enc=enc, ciphertext=sealed_welcome))

		# 4. Bob consumes his Welcomes queue stream
		stream = stub.ListenWelcomes(mls_pb2.ListenRequest(identity="bob"))

		# We use `async for` or just pull the first message
		first_welcome = await stream.read()

		# Bob unseals it over the gRPC wire
		pt_welcome = HPKE.open(bob_kem, first_welcome.enc, first_welcome.ciphertext, aad=b"grpc_welcome", info=b"mls10-welcome")
		received_welcome = Welcome.from_bytes(pt_welcome)

		# Bob mathematically joins the Sovereign Group!
		bob_group = MLSGroup.join(received_welcome, bob_sig, bob_kem)

		# Verify consensus
		assert alice_next.application_key == bob_group.application_key
		assert alice_next.epoch_id == 1
		assert bob_group.epoch_id == 1

		# Cleanup stream
		stream.cancel()

	finally:
		await server.stop(grace=None)
