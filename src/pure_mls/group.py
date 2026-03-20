import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from pure_mls.epoch import EpochState
from pure_mls.hkdf import hkdf_expand
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.keyschedule import KeySchedule
from pure_mls.tree import KeyPackage, LeafNode, ParentNode, RatchetTree


@dataclass
class WelcomeInfo:
	"""Information needed for a new member to join the group."""

	group_id: bytes
	epoch_id: int
	tree: RatchetTree
	joiner_secret: bytes
	confirmed_transcript_hash: bytes
	joiner_index: int

	def to_bytes(self) -> bytes:
		from cryptography.hazmat.primitives import hmac as crypto_hmac
		from cryptography.hazmat.primitives.hashes import SHA256

		VERSION = b"\x02"
		tree_bytes = self.tree.to_bytes()
		tree_len = len(tree_bytes).to_bytes(4, "big")
		epoch_bytes = self.epoch_id.to_bytes(8, "big")
		group_id_len = len(self.group_id).to_bytes(2, "big")

		payload = (
			VERSION
			+ group_id_len
			+ self.group_id
			+ epoch_bytes
			+ tree_len
			+ tree_bytes
			+ self.joiner_secret
			+ self.confirmed_transcript_hash
			+ self.joiner_index.to_bytes(4, "big")
		)

		h = crypto_hmac.HMAC(self.confirmed_transcript_hash[:32], SHA256())
		h.update(payload)
		return payload + h.finalize()

	@classmethod
	def from_bytes(cls, data: bytes) -> "WelcomeInfo":
		from cryptography.hazmat.primitives import hmac as crypto_hmac
		from cryptography.hazmat.primitives.hashes import SHA256

		if data[0] != 0x02:
			raise ValueError("Unsupported WelcomeInfo version")

		payload_without_mac = data[:-32]
		mac = data[-32:]

		offset = 1
		group_id_len = int.from_bytes(data[offset : offset + 2], "big")
		offset += 2
		group_id = data[offset : offset + group_id_len]
		offset += group_id_len
		epoch_id = int.from_bytes(data[offset : offset + 8], "big")
		offset += 8
		tree_len = int.from_bytes(data[offset : offset + 4], "big")
		offset += 4
		tree_bytes = data[offset : offset + tree_len]
		offset += tree_len
		joiner_secret = data[offset : offset + 32]
		offset += 32
		confirmed_transcript_hash = data[offset : offset + 32]

		h = crypto_hmac.HMAC(confirmed_transcript_hash, SHA256())
		h.update(payload_without_mac)
		h.verify(mac)

		offset += 32
		joiner_index = int.from_bytes(data[offset : offset + 4], "big")

		tree = RatchetTree.from_bytes(tree_bytes)
		return cls(group_id, epoch_id, tree, joiner_secret, confirmed_transcript_hash, joiner_index)


@dataclass
class GroupUpdate:
	"""A conceptual Commit message containing the new tree and HPKE-encrypted commit_secrets for peers."""

	epoch_id: int
	tree: RatchetTree
	encrypted_commit_secrets: dict[bytes, bytes]
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
		# In full MLS, the committer generates a new path secret and encrypts it to the copath.
		commit_secret = os.urandom(32)

		encrypted_secrets = {}
		for i, node in enumerate(new_tree.nodes):
			if isinstance(node, LeafNode) and i != self.my_index:
				pk = node.public_key
				enc, ct = HPKE.seal(pk, commit_secret)
				encrypted_secrets[pk] = enc + ct

		# 3. Advance the epoch
		# TODO (STATE-02): Transcript Hash Covers only epoch_id and commit_secret.
		# Should cover full commit framing (sender, proposals, group_id) in a production setup.
		transcript_hash = hashlib.sha256(
			(self.state.epoch_id + 1).to_bytes(8, "big") + commit_secret + new_tree.to_bytes() + self.state.key_schedule.confirmation_key
		).digest()
		next_state = self.state.advance_epoch(commit_secret, new_tree, transcript_hash=transcript_hash)

		# Sign the update payload to prevent Commit Forgery (High Remediation)
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
		# The joiner derives the schedule using the joiner_secret and a blank commit_secret (?)
		# In RFC 9420, the Welcome contains the encrypted joiner_secret.
		# For this implementation, we re-derive from joiner_secret directly.
		# Mix confirmed_transcript_hash into epoch_secret derivation to prevent Welcome Spoofing
		joiner_context = welcome.confirmed_transcript_hash
		epoch_secret = hkdf_expand(welcome.joiner_secret, joiner_context, 32, hashlib.sha256)
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

		# 1. Decrypt Commit Secret (P0 Remediation)
		my_kem_pub = self.my_kem_key.public_bytes()
		if my_kem_pub not in update.encrypted_commit_secrets:
			raise ValueError("Not invited to this epoch (missing encrypted commit_secret)")

		enc_ct = update.encrypted_commit_secrets[my_kem_pub]
		enc, ct = enc_ct[:32], enc_ct[32:]
		commit_secret = HPKE.open(self.my_kem_key, enc, ct)

		# 2. Verify Signature (High Remediation)
		try:
			public_key = ed25519.Ed25519PublicKey.from_public_bytes(committer_node.key_package.identity_key_pub)
			transcript_hash = hashlib.sha256(
				update.epoch_id.to_bytes(8, "big") + commit_secret + update.tree.to_bytes() + self.state.key_schedule.confirmation_key
			).digest()
			public_key.verify(update.signature, transcript_hash)
		except InvalidSignature:
			raise ValueError("Commit Forgery Detected: Invalid Signature in update")
		except Exception:
			raise ValueError("Invalid signature format")

		next_state = self.state.advance_epoch(commit_secret, update.tree, transcript_hash=transcript_hash)
		return MLSGroup(next_state, self.my_index, self.my_sig_key, self.my_kem_key)
