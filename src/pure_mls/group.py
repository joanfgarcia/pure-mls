import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from pure_mls.epoch import EpochState
from pure_mls.hkdf import hkdf_extract
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.keyschedule import KeySchedule
from pure_mls.tree import KeyPackage, LeafNode, ParentNode, RatchetTree


@dataclass
class WelcomeInfo:
	"""Information needed for a new member to join the group.

	SECURITY: joiner_secret is included in the serialized form.
	Callers MUST seal this struct with HPKE before transmission.
	Exposing it in plaintext compromises the full epoch key schedule.
	"""

	group_id: bytes
	epoch_id: int
	tree: RatchetTree
	joiner_secret: bytes
	confirmed_transcript_hash: bytes
	joiner_index: int


	def encrypt_application_message(self, plaintext: bytes) -> bytes:
		"""
		Encrypts an application message for this epoch using AES-GCM.
		RFC 9420: Uses the epoch's encryption_secret.
		"""
		from cryptography.hazmat.primitives.ciphers.aead import AESGCM
		
		aesgcm = AESGCM(self.application_key)
		nonce = os.urandom(12)  # 96-bit nonce
		# We use the group_id + epoch_id as Associated Data (AD) for integrity
		ad = self.group_id + self.epoch_id.to_bytes(8, "big")
		ciphertext = aesgcm.encrypt(nonce, plaintext, ad)
		
		# Payload: [nonce (12)] + [ciphertext (tag+data)]
		return nonce + ciphertext

	def decrypt_application_message(self, payload: bytes) -> bytes:
		"""
		Decrypts an application message for this epoch.
		"""
		from cryptography.hazmat.primitives.ciphers.aead import AESGCM
		
		if len(payload) < 28:
			raise ValueError("Application message payload too short")
			
		nonce = payload[:12]
		ciphertext = payload[12:]
		
		aesgcm = AESGCM(self.application_key)
		ad = self.group_id + self.epoch_id.to_bytes(8, "big")
		
		try:
			return aesgcm.decrypt(nonce, ciphertext, ad)
		except Exception as e:
			raise ValueError(f"Application message decryption failed: {e}")

	def to_bytes(self) -> bytes:
		VERSION = b"\x03"
		tree_bytes = self.tree.to_bytes()
		body = (
			VERSION
			+ len(self.group_id).to_bytes(2, "big")
			+ self.group_id
			+ self.epoch_id.to_bytes(8, "big")
			+ len(tree_bytes).to_bytes(4, "big")
			+ tree_bytes
			+ self.joiner_secret
			+ self.confirmed_transcript_hash
			+ self.joiner_index.to_bytes(4, "big")
		)
		mac = hmac.new(self.joiner_secret, body, hashlib.sha256).digest()
		return body + mac

	@classmethod
	def from_bytes(cls, data: bytes) -> "WelcomeInfo":
		if data[0] != 0x03:
			raise ValueError("Unsupported WelcomeInfo version")

		body, received_mac = data[:-32], data[-32:]
		offset = 1
		group_id_len = int.from_bytes(body[offset : offset + 2], "big")
		offset += 2
		group_id = body[offset : offset + group_id_len]
		offset += group_id_len
		epoch_id = int.from_bytes(body[offset : offset + 8], "big")
		offset += 8
		tree_len = int.from_bytes(body[offset : offset + 4], "big")
		offset += 4
		tree_bytes = body[offset : offset + tree_len]
		offset += tree_len
		joiner_secret = body[offset : offset + 32]
		offset += 32
		confirmed_transcript_hash = body[offset : offset + 32]
		offset += 32
		joiner_index = int.from_bytes(body[offset : offset + 4], "big")

		expected_mac = hmac.new(joiner_secret, body, hashlib.sha256).digest()
		if not hmac.compare_digest(received_mac, expected_mac):
			raise ValueError("WelcomeInfo integrity check failed: HMAC mismatch")

		tree = RatchetTree.from_bytes(tree_bytes)
		return cls(group_id, epoch_id, tree, joiner_secret, confirmed_transcript_hash, joiner_index)


@dataclass
class GroupUpdate:
	"""A conceptual Commit message containing the new tree and HPKE-encrypted commit_secrets for peers."""

	epoch_id: int
	tree: RatchetTree
	encrypted_commit_secrets: dict[int, bytes]
	committer_index: int
	signature: bytes


class MLSGroup:
	"""
	High-level state machine for an MLS Group.
	Manages the current EpochState and transitions.
	"""

	def __init__(self, state: EpochState, my_index: int, my_sig_key: SignatureKey, my_kem_key: KemKey):
		self.state = state
		self.my_index = my_index
		self.my_sig_key = my_sig_key
		self.my_kem_key = my_kem_key

	@property
	def group_id(self) -> bytes:
		return self.state.group_id

	@property
	def epoch_id(self) -> int:
		return self.state.epoch_id

	@property
	def application_key(self) -> bytes:
		"""The symmetric key used to encrypt application messages in this epoch."""
		return self.state.key_schedule.encryption_secret

	@classmethod
	def create(cls, group_id: bytes, creator_sig_key: SignatureKey, creator_kem_key: KemKey) -> "MLSGroup":
		"""
		Initialize a new MLS group (Genesis).
		The creator becomes leaf 0.
		"""
		tree = RatchetTree(num_leaves=1)
		kp = KeyPackage(identity_key_pub=creator_sig_key.public_bytes(), init_key_pub=creator_kem_key.public_bytes())
		tree.set_leaf(0, LeafNode(key_package=kp))

		state = EpochState.genesis(group_id, tree)
		return cls(state, my_index=0, my_sig_key=creator_sig_key, my_kem_key=creator_kem_key)

	def add_member(self, key_package: KeyPackage) -> tuple["MLSGroup", WelcomeInfo, GroupUpdate]:
		"""
		Adds a new member, generating a Commit and advancing the Epoch.
		Returns the updated Group, the Welcome for the joiner, and the Update for peers.
		(Simplified: we just append to the tree, rebuild the direct path, and derive a new commit_secret).
		"""
		# 1. Expand tree by 1 leaf
		new_num_leaves = self.state.tree.num_leaves + 1
		new_tree = RatchetTree(num_leaves=new_num_leaves)

		# Copy existing nodes (simplification)
		for i, node in enumerate(self.state.tree.nodes):
			if node is not None:
				if isinstance(node, LeafNode):
					new_tree.set_leaf(i, node)
				elif isinstance(node, ParentNode):
					new_tree.set_parent(i, node)

		# Insert the new leaf at the next available even index
		new_leaf_idx = (new_num_leaves - 1) * 2
		new_tree.set_leaf(new_leaf_idx, LeafNode(key_package=key_package))

		# 2. Re-randomize the root secret (Simulated Commit)
		commit_secret = os.urandom(32)

		encrypted_secrets = {}
		for i, node in enumerate(new_tree.nodes):
			if isinstance(node, LeafNode) and i != self.my_index:
				pk = node.public_key
				# HPKE context isolation (CRIT-01)
				enc, ct = HPKE.seal(pk, commit_secret, info=b"mls10-commit-secret")
				encrypted_secrets[i] = enc + ct

		# 3. Advance the epoch
		ciphertexts_bytes = b"".join(k.to_bytes(4, "big") + v for k, v in sorted(encrypted_secrets.items()))
		transcript_hash = hashlib.sha256(
			(self.state.epoch_id + 1).to_bytes(8, "big") + new_tree.to_bytes() + self.state.key_schedule.confirmation_key + ciphertexts_bytes
		).digest()
		next_state = self.state.advance_epoch(commit_secret, new_tree, transcript_hash=transcript_hash)

		# Sign the update payload to prevent Commit Forgery
		signature = self.my_sig_key.sign(transcript_hash)

		# 4. Construct Welcome and Update
		welcome = WelcomeInfo(
			group_id=self.group_id,
			epoch_id=next_state.epoch_id,
			tree=new_tree,
			joiner_secret=next_state.key_schedule.joiner_secret,
			confirmed_transcript_hash=transcript_hash,
			joiner_index=new_leaf_idx,
		)
		update = GroupUpdate(
			epoch_id=next_state.epoch_id,
			tree=new_tree,
			encrypted_commit_secrets=encrypted_secrets,
			committer_index=self.my_index,
			signature=signature,
		)

		# Return mutated self
		new_group = MLSGroup(next_state, self.my_index, self.my_sig_key, self.my_kem_key)
		return new_group, welcome, update

	@classmethod
	def join(cls, welcome: WelcomeInfo, my_sig_key: SignatureKey, my_kem_key: KemKey) -> "MLSGroup":
		"""
		Initializes a Group instance from a Welcome message.
		Recalculates the EpochState and KeySchedule.
		"""
		# The joiner derives the schedule using the joiner_secret and a blank commit_secret (zero vector).
		# Mix confirmed_transcript_hash indirectly downstream through the KeySchedule expansion if needed.
		epoch_secret = hkdf_extract(b"\x00" * 32, welcome.joiner_secret, hashlib.sha256)
		ks = KeySchedule._from_epoch_secret(epoch_secret, welcome.joiner_secret)

		state = EpochState(group_id=welcome.group_id, epoch_id=welcome.epoch_id, tree=welcome.tree, key_schedule=ks)

		return cls(state, my_index=welcome.joiner_index, my_sig_key=my_sig_key, my_kem_key=my_kem_key)

	def process_update(self, update: GroupUpdate) -> "MLSGroup":
		"""
		Process a Commit from another member.
		Advances local state using the new tree and decrypted commit_secret.
		"""
		if update.epoch_id != self.epoch_id + 1:
			raise ValueError("Out of order update")

		committer_node = self.state.tree.get_node(update.committer_index)
		if not isinstance(committer_node, LeafNode):
			raise ValueError("Invalid committer index")

		# 1. Verify Signature FIRST to prevent padding oracles (STATE-04)
		ciphertexts_bytes = b"".join(k.to_bytes(4, "big") + v for k, v in sorted(update.encrypted_commit_secrets.items()))
		try:
			public_key = ed25519.Ed25519PublicKey.from_public_bytes(committer_node.key_package.identity_key_pub)
			transcript_hash = hashlib.sha256(
				update.epoch_id.to_bytes(8, "big") + update.tree.to_bytes() + self.state.key_schedule.confirmation_key + ciphertexts_bytes
			).digest()
			public_key.verify(update.signature, transcript_hash)
		except InvalidSignature:
			raise ValueError("Commit Forgery Detected: Invalid Signature in update")
		except Exception:
			raise ValueError("Invalid signature format")

		# 2. HPKE Decapsulate only authentic ciphertexts
		if self.my_index not in update.encrypted_commit_secrets:
			raise ValueError(f"Not invited to this epoch (Leaf Index {self.my_index} not found in update)")

		enc_ct = update.encrypted_commit_secrets[self.my_index]
		enc, ct = enc_ct[:32], enc_ct[32:]
		# HPKE context isolation (CRIT-01)
		commit_secret = HPKE.open(self.my_kem_key, enc, ct, info=b"mls10-commit-secret")

		next_state = self.state.advance_epoch(commit_secret, update.tree, transcript_hash=transcript_hash)
		return MLSGroup(next_state, self.my_index, self.my_sig_key, self.my_kem_key)


	def encrypt_application_message(self, plaintext: bytes) -> bytes:
		"""
		Encrypts an application message for this epoch using AES-GCM.
		RFC 9420: Uses the epoch's encryption_secret.
		"""
		from cryptography.hazmat.primitives.ciphers.aead import AESGCM
		
		aesgcm = AESGCM(self.application_key)
		nonce = os.urandom(12)  # 96-bit nonce
		# We use the group_id + epoch_id as Associated Data (AD) for integrity
		ad = self.group_id + self.epoch_id.to_bytes(8, "big")
		ciphertext = aesgcm.encrypt(nonce, plaintext, ad)
		
		# Payload: [nonce (12)] + [ciphertext (tag+data)]
		return nonce + ciphertext

	def decrypt_application_message(self, payload: bytes) -> bytes:
		"""
		Decrypts an application message for this epoch.
		"""
		from cryptography.hazmat.primitives.ciphers.aead import AESGCM
		
		if len(payload) < 28:
			raise ValueError("Application message payload too short")
			
		nonce = payload[:12]
		ciphertext = payload[12:]
		
		aesgcm = AESGCM(self.application_key)
		ad = self.group_id + self.epoch_id.to_bytes(8, "big")
		
		try:
			return aesgcm.decrypt(nonce, ciphertext, ad)
		except Exception as e:
			raise ValueError(f"Application message decryption failed: {e}")

	def to_bytes(self) -> bytes:
		"""Serializes the full state + my private keys (Danger Zone)."""
		state_bytes = self.state.to_bytes()
		return (
			self.my_index.to_bytes(4, "big")
			+ self.my_sig_key.private_bytes()
			+ self.my_kem_key.private_bytes()
			+ len(state_bytes).to_bytes(4, "big")
			+ state_bytes
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "MLSGroup":
		offset = 0
		idx = int.from_bytes(data[offset : offset + 4], "big")
		offset += 4
		sig_key = SignatureKey.from_private_bytes(data[offset : offset + 32])
		offset += 32
		kem_key = KemKey.from_private_bytes(data[offset : offset + 32])
		offset += 32
		s_len = int.from_bytes(data[offset : offset + 4], "big")
		offset += 4
		state = EpochState.from_bytes(data[offset : offset + s_len])
		return cls(state, my_index=idx, my_sig_key=sig_key, my_kem_key=kem_key)
