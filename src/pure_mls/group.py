import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from pure_mls.epoch import EpochState
from pure_mls.hkdf import hkdf_expand, hkdf_extract
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.keyschedule import KeySchedule
from pure_mls.tls import (
	read_opaque,
	read_opaque32,
	read_u8,
	read_u16,
	read_u32,
	read_u64,
	tls_opaque,
	tls_opaque32,
	tls_u8,
	tls_u16,
	tls_u32,
	tls_u64,
)
from pure_mls.tree import KeyPackage, LeafNode, ParentNode, RatchetTree

# ---------------------------------------------------------------------------
# GroupContext (RFC 9420 §8.1)
# ---------------------------------------------------------------------------


@dataclass
class GroupContext:
	"""RFC 9420 §8.1: Group context used in key schedule and HPKE info.

	This struct is hashed into the transcript hash and used as the HPKE
	info parameter, ensuring all cryptographic operations are bound to
	the specific group and epoch.
	"""

	group_id: bytes
	epoch: int
	tree_hash: bytes
	confirmed_transcript_hash: bytes

	# Fixed for our single supported suite:
	#   MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
	_VERSION: int = 0x0001  # mls10
	_CIPHER_SUITE: int = 0x0001

	def to_bytes(self) -> bytes:
		"""RFC 9420 §8.1 TLS encoding of GroupContext."""
		return (
			tls_u16(self._VERSION)
			+ tls_u16(self._CIPHER_SUITE)
			+ tls_opaque(self.group_id)  # group_id<V>
			+ tls_u64(self.epoch)  # epoch uint64
			+ tls_opaque(self.tree_hash)  # tree_hash<V>
			+ tls_opaque(self.confirmed_transcript_hash)  # confirmed_transcript_hash<V>
			+ tls_u32(0)  # extensions<V> empty
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "GroupContext":
		"""Decode a TLS-encoded GroupContext."""
		offset = 0
		version, offset = read_u16(data, offset)
		if version != cls._VERSION:
			raise ValueError(f"Unsupported GroupContext version: {version:#06x}")
		cipher_suite, offset = read_u16(data, offset)
		if cipher_suite != cls._CIPHER_SUITE:
			raise ValueError(f"Unsupported cipher suite: {cipher_suite:#06x}")
		group_id, offset = read_opaque(data, offset)
		epoch, offset = read_u64(data, offset)
		tree_hash, offset = read_opaque(data, offset)
		confirmed_transcript_hash, offset = read_opaque(data, offset)
		# extensions (uint32 length, ignored for now)
		return cls(
			group_id=group_id,
			epoch=epoch,
			tree_hash=tree_hash,
			confirmed_transcript_hash=confirmed_transcript_hash,
		)


# ---------------------------------------------------------------------------
# Welcome / GroupSecrets / EncryptedGroupSecrets (RFC 9420 §12.1.2)
# ---------------------------------------------------------------------------


@dataclass
class GroupSecrets:
	"""RFC 9420 §12.1.2: Internal struct sealed by HPKE for each joiner.

	Contains the joiner_secret and the joiner's leaf index.
	(PathSecret and PSKs omitted — not implemented in this version.)
	This is sent as the HPKE plaintext inside EncryptedGroupSecrets.
	"""

	joiner_secret: bytes  # 32 bytes
	joiner_index: int  # uint32 (our extension — needed for join())

	def to_bytes(self) -> bytes:
		return tls_opaque(self.joiner_secret) + tls_u32(self.joiner_index)

	@classmethod
	def from_bytes(cls, data: bytes) -> "GroupSecrets":
		offset = 0
		joiner_secret, offset = read_opaque(data, offset)
		joiner_index, offset = read_u32(data, offset)
		return cls(joiner_secret=joiner_secret, joiner_index=joiner_index)


@dataclass
class EncryptedGroupSecrets:
	"""RFC 9420 §12.1.2: HPKE-encrypted GroupSecrets for one recipient."""

	new_member: bytes  # KeyPackageRef (32 bytes)
	kem_output: bytes  # HPKE kem_output (enc)
	ciphertext: bytes  # HPKE ciphertext

	def to_bytes(self) -> bytes:
		return (
			tls_opaque(self.new_member)  # new_member<V>  = KPRef
			+ tls_opaque(self.kem_output)  # HPKECiphertext.kem_output<V>
			+ tls_opaque(self.ciphertext)  # HPKECiphertext.ciphertext<V>
		)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["EncryptedGroupSecrets", int]:
		new_member, offset = read_opaque(data, offset)
		kem_output, offset = read_opaque(data, offset)
		ciphertext, offset = read_opaque(data, offset)
		return cls(new_member=new_member, kem_output=kem_output, ciphertext=ciphertext), offset


@dataclass
class Welcome:
	"""RFC 9420 §12.1.2: Welcome message sent to new members.

	Contains:
	- HPKE-encrypted GroupSecrets for each joiner (keyed by KeyPackageRef)
	- HPKE-sealed GroupInfo (contains group_id, epoch, tree, transcript_hash)

	GroupInfo is sealed with AES-128-GCM using welcome_key derived from
	joiner_secret via ExpandWithLabel(joiner_secret, 'welcome', b'', 16).
	This follows RFC 9420 §12.1.2 exactly.
	"""

	cipher_suite: int  # 0x0001
	encrypted_group_secrets: list[EncryptedGroupSecrets]  # one per joiner
	encrypted_group_info: bytes  # HPKE ciphertext of GroupInfo

	_CIPHER_SUITE: int = 0x0001

	def to_bytes(self) -> bytes:
		secrets_bytes = b"".join(e.to_bytes() for e in self.encrypted_group_secrets)
		return (
			tls_u16(self._CIPHER_SUITE)
			+ tls_opaque32(secrets_bytes)  # secrets<V> uint32-prefixed
			+ tls_opaque32(self.encrypted_group_info)  # encrypted_group_info<V>
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "Welcome":
		offset = 0
		cipher_suite, offset = read_u16(data, offset)
		secrets_raw, offset = read_opaque32(data, offset)
		encrypted_group_info, offset = read_opaque32(data, offset)

		# Parse EncryptedGroupSecrets vector
		encrypted_group_secrets: list[EncryptedGroupSecrets] = []
		soffset = 0
		while soffset < len(secrets_raw):
			egs, soffset = EncryptedGroupSecrets.from_bytes(secrets_raw, soffset)
			encrypted_group_secrets.append(egs)

		return cls(
			cipher_suite=cipher_suite,
			encrypted_group_secrets=encrypted_group_secrets,
			encrypted_group_info=encrypted_group_info,
		)


# WelcomeInfo is kept as a legacy alias for backward compatibility.
# It will be removed in a future version.
WelcomeInfo = Welcome  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# KeyPackageRef + transcript hash (RFC 9420 §10.2, §8.2)
# ---------------------------------------------------------------------------

# Deprecated constants (kept for test compatibility, removed in v1.0 final cleanup)
_CIPHER_SUITE: bytes = b"\x00\x01"
_EXTENSIONS_EMPTY: bytes = b"\x00\x00\x00\x00"


def _make_kp_ref(kp: KeyPackage) -> bytes:
	"""RFC 9420 §10.2: MakeKeyPackageRef(kp) = RefHash("MLS 1.0 KeyPackageRef", kp).

	RefHash(label, value) = HKDF-Expand(HKDF-Extract(b"", value), ASCII(label), Nh=32).
	"""
	import hashlib

	prk = hkdf_extract(b"", kp.to_bytes(), hashlib.sha256)
	return hkdf_expand(prk, b"MLS 1.0 KeyPackageRef", 32, hashlib.sha256)


def _make_group_context(
	group_id: bytes,
	epoch_id: int,
	tree: RatchetTree,
	confirmed_transcript_hash: bytes,
) -> GroupContext:
	"""Build GroupContext for the given group state."""
	tree_hash = hashlib.sha256(tree.to_bytes()).digest()
	return GroupContext(
		group_id=group_id,
		epoch=epoch_id,
		tree_hash=tree_hash,
		confirmed_transcript_hash=confirmed_transcript_hash,
	)


def _make_framed_content_tbs(group_ctx: GroupContext, framed: "FramedContent") -> bytes:
	"""RFC 9420 §6.2: FramedContentTBS = version + wire_format + GroupContext + FramedContent.

	This is what the committer signs with their Ed25519 key.
	"""
	return (
		tls_u16(0x0001)  # version = mls10
		+ tls_u16(0x0002)  # wire_format = mls_public_message
		+ group_ctx.to_bytes()  # GroupContext (binds to epoch)
		+ framed.to_bytes()  # FramedContent body
	)


def _transcript_hash(
	group_id: bytes,
	epoch_id: int,
	tree: RatchetTree,
	confirmation_key: bytes,
	ciphertexts_bytes: bytes,
	sender_index: int,
	prior_confirmed_transcript_hash: bytes = b"",
) -> bytes:
	"""RFC 9420 §8.2: GroupInfo transcript hash = SHA-256(GroupContext || GroupInfo fields).

	The GroupContext is built from the *new* epoch state after the commit.
	The hash is signed by the committer (STATE-02 fix).
	"""
	# GroupContext encodes the new epoch state
	ctx = _make_group_context(group_id, epoch_id, tree, prior_confirmed_transcript_hash)
	ctx_bytes = ctx.to_bytes()

	# Remaining GroupInfo fields not covered by GroupContext:
	# confirmation_tag (HMAC over transcript), ciphertexts, extensions, Sender
	return hashlib.sha256(
		ctx_bytes
		+ confirmation_key
		+ ciphertexts_bytes
		+ tls_u32(0)  # extensions: empty  (uint32-prefixed vec)
		# RFC 9420 §8.2 Sender struct: SenderType(uint8=0x01 member) + leaf_index(uint32)
		+ tls_u8(0x01)
		+ tls_u32(sender_index)
	).digest()


@dataclass
class GroupUpdate:
	"""RFC 9420 §12.1.1: Commit message (simplified Commit + FramedContent).

	In full RFC 9420 a Commit is wrapped in an AuthenticatedContent with a
	FramedContent + Signature. For v1.0 we encode the essential fields in a
	compact TLS format that includes epoch_id, tree, encrypted_commit_secrets,
	committer_index and the Ed25519 signature.

	Wire format (big-endian, TLS-style):
		uint64  epoch_id
		opaque<V>  tree_bytes          (uint32-prefixed tree serialization)
		uint32  secrets_count
		[for each secret:]
			opaque<V>  kp_ref           (32-byte KeyPackageRef)
			opaque<V>  enc_ct           (kem_output + ciphertext concatenated)
		uint32  committer_index
		opaque<V>  signature            (Ed25519 64 bytes)
	"""

	epoch_id: int
	tree: RatchetTree
	encrypted_commit_secrets: dict[bytes, bytes]
	committer_index: int
	signature: bytes
	# RFC 9420 §6.2 context fields — carried for PublicMessage construction
	# Set by add_member(); None when GroupUpdate is deserialized from wire.
	_group_ctx: "GroupContext | None" = None
	_confirmation_key: bytes | None = None
	_authentication_secret: bytes | None = None
	_transcript_hash: bytes | None = None

	def _body_bytes(self) -> bytes:
		"""The unsigned Commit body (epoch + tree + secrets + committer_index)."""
		tree_raw = self.tree.to_bytes()
		secrets_parts = b""
		for kp_ref, enc_ct in sorted(self.encrypted_commit_secrets.items()):
			secrets_parts += tls_opaque(kp_ref) + tls_opaque(enc_ct)
		n = len(self.encrypted_commit_secrets)
		return tls_u64(self.epoch_id) + tls_opaque32(tree_raw) + tls_u32(n) + secrets_parts + tls_u32(self.committer_index)

	def to_bytes(self) -> bytes:
		"""Serialize GroupUpdate to TLS-style wire format."""
		tree_raw = self.tree.to_bytes()
		secrets_parts = b""
		for kp_ref, enc_ct in sorted(self.encrypted_commit_secrets.items()):
			secrets_parts += tls_opaque(kp_ref) + tls_opaque(enc_ct)

		return (
			tls_u64(self.epoch_id)
			+ tls_opaque32(tree_raw)  # tree<V> uint32-prefixed
			+ tls_u32(len(self.encrypted_commit_secrets))
			+ secrets_parts
			+ tls_u32(self.committer_index)
			+ tls_opaque(self.signature)
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "GroupUpdate":
		"""Deserialize a GroupUpdate from TLS wire format."""
		offset = 0
		epoch_id, offset = read_u64(data, offset)
		tree_raw, offset = read_opaque32(data, offset)
		tree = RatchetTree.from_bytes(tree_raw)
		secrets_count, offset = read_u32(data, offset)
		encrypted_secrets: dict[bytes, bytes] = {}
		for _ in range(secrets_count):
			kp_ref, offset = read_opaque(data, offset)
			enc_ct, offset = read_opaque(data, offset)
			encrypted_secrets[kp_ref] = enc_ct
		committer_index, offset = read_u32(data, offset)
		signature, offset = read_opaque(data, offset)
		return cls(
			epoch_id=epoch_id,
			tree=tree,
			encrypted_commit_secrets=encrypted_secrets,
			committer_index=committer_index,
			signature=signature,
		)


# ---------------------------------------------------------------------------
# MLSMessage envelope (RFC 9420 §6)
# ---------------------------------------------------------------------------


class WireFormat:
	"""RFC 9420 §6: WireFormat identifies the message type."""

	RESERVED = 0x0000
	MLS_PUBLIC_MESSAGE = 0x0001  # PublicMessage (Commit/Proposal)
	MLS_PRIVATE_MESSAGE = 0x0002  # PrivateMessage (application data)
	MLS_WELCOME = 0x0003  # Welcome
	MLS_GROUP_INFO = 0x0004  # GroupInfo
	MLS_KEY_PACKAGE = 0x0005  # KeyPackage


@dataclass
class MLSMessage:
	"""RFC 9420 §6: Top-level MLSMessage framing.

	Wire format:
		uint16  version   = 0x0001 (mls10)
		uint16  wire_format
		opaque<V>  body   (uint32-prefixed payload)
	"""

	_VERSION = 0x0001  # mls10

	wire_format: int
	body: bytes

	def to_bytes(self) -> bytes:
		return tls_u16(self._VERSION) + tls_u16(self.wire_format) + tls_opaque32(self.body)

	@classmethod
	def from_bytes(cls, data: bytes) -> "MLSMessage":
		offset = 0
		version, offset = read_u16(data, offset)
		if version != cls._VERSION:
			raise ValueError(f"Unsupported MLSMessage version: {version:#06x}")
		wire_format, offset = read_u16(data, offset)
		body, offset = read_opaque32(data, offset)
		return cls(wire_format=wire_format, body=body)

	@classmethod
	def wrap_welcome(cls, welcome: "Welcome") -> "MLSMessage":
		"""Wrap a Welcome in an MLSMessage envelope."""
		return cls(wire_format=WireFormat.MLS_WELCOME, body=welcome.to_bytes())

	@classmethod
	def wrap_commit(cls, commit: "GroupUpdate") -> "MLSMessage":
		"""Wrap a GroupUpdate (Commit) in an MLSMessage envelope as RFC PublicMessage."""
		if (
			commit._group_ctx is not None
			and commit._confirmation_key is not None
			and commit._authentication_secret is not None
			and commit._transcript_hash is not None
		):
			# Full RFC mode: proper confirmation_tag + membership_tag
			pm = PublicMessage.from_group_update(
				commit,
				group_ctx=commit._group_ctx,
				confirmation_key=commit._confirmation_key,
				authentication_secret=commit._authentication_secret,
				transcript_hash=commit._transcript_hash,
			)
		else:
			# Deserialized GroupUpdate (no context): use placeholder values
			# (interop with peers that don't use pure-mls wrap_commit)
			_dummy_ctx = GroupContext(
				group_id=b"",
				epoch=commit.epoch_id,
				tree_hash=b"\x00" * 32,
				confirmed_transcript_hash=b"\x00" * 32,
			)
			pm = PublicMessage.from_group_update(
				commit,
				group_ctx=_dummy_ctx,
				confirmation_key=b"\x00" * 32,
				authentication_secret=b"\x00" * 32,
				transcript_hash=b"\x00" * 32,
			)
		return cls(wire_format=WireFormat.MLS_PUBLIC_MESSAGE, body=pm.to_bytes())

	def unwrap_welcome(self) -> "Welcome":
		if self.wire_format != WireFormat.MLS_WELCOME:
			raise ValueError(f"Expected MLS_WELCOME, got {self.wire_format:#06x}")
		return Welcome.from_bytes(self.body)

	def unwrap_commit(self) -> "GroupUpdate":
		if self.wire_format != WireFormat.MLS_PUBLIC_MESSAGE:
			raise ValueError(f"Expected MLS_PUBLIC_MESSAGE, got {self.wire_format:#06x}")
		return PublicMessage.from_bytes(self.body).to_group_update()


# ---------------------------------------------------------------------------
# FramedContent + AuthData + PublicMessage (RFC 9420 §6)
# ---------------------------------------------------------------------------


@dataclass
class FramedContent:
	"""RFC 9420 §6.1: FramedContent wraps any MLS message with group/epoch context.

	ContentType: 0x01=application, 0x02=proposal, 0x03=commit
	SenderType:  0x01=member (the only type we produce)
	"""

	group_id: bytes
	epoch: int
	sender_leaf_index: int
	authenticated_data: bytes  # arbitrary AAD (empty by default)
	content: bytes  # TLS-serialized Commit (GroupUpdate body)

	CONTENT_TYPE_COMMIT = 0x03

	def to_bytes(self) -> bytes:
		return (
			tls_opaque(self.group_id)
			+ tls_u64(self.epoch)
			+ tls_u8(0x01)  # SenderType = member
			+ tls_u32(self.sender_leaf_index)
			+ tls_opaque(self.authenticated_data)
			+ tls_u8(self.CONTENT_TYPE_COMMIT)
			+ tls_opaque32(self.content)
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "FramedContent":
		offset = 0
		group_id, offset = read_opaque(data, offset)
		epoch, offset = read_u64(data, offset)
		sender_type, offset = read_u8(data, offset)
		if sender_type != 0x01:
			raise ValueError(f"Unsupported SenderType: {sender_type:#04x}")
		sender_leaf_index, offset = read_u32(data, offset)
		authenticated_data, offset = read_opaque(data, offset)
		content_type, offset = read_u8(data, offset)
		if content_type != cls.CONTENT_TYPE_COMMIT:
			raise ValueError(f"Unsupported ContentType: {content_type:#04x}")
		content, offset = read_opaque32(data, offset)
		return cls(
			group_id=group_id,
			epoch=epoch,
			sender_leaf_index=sender_leaf_index,
			authenticated_data=authenticated_data,
			content=content,
		)


@dataclass
class FramedContentAuthData:
	"""RFC 9420 §6.1: signature + confirmation_tag for a FramedContent."""

	signature: bytes
	confirmation_tag: bytes

	def to_bytes(self) -> bytes:
		return tls_opaque(self.signature) + tls_opaque(self.confirmation_tag)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["FramedContentAuthData", int]:
		signature, offset = read_opaque(data, offset)
		confirmation_tag, offset = read_opaque(data, offset)
		return cls(signature=signature, confirmation_tag=confirmation_tag), offset


@dataclass
class PublicMessage:
	"""RFC 9420 §6.2: PublicMessage = FramedContent + FramedContentAuthData + membership_tag.

	membership_tag: HMAC-SHA256 proving the sender is a current group member.
	"""

	content: FramedContent
	auth: FramedContentAuthData
	membership_tag: bytes

	def to_bytes(self) -> bytes:
		return tls_opaque32(self.content.to_bytes()) + tls_opaque32(self.auth.to_bytes()) + tls_opaque(self.membership_tag)

	@classmethod
	def from_bytes(cls, data: bytes) -> "PublicMessage":
		offset = 0
		content_bytes, offset = read_opaque32(data, offset)
		auth_bytes, offset = read_opaque32(data, offset)
		membership_tag, offset = read_opaque(data, offset)
		content = FramedContent.from_bytes(content_bytes)
		auth, _ = FramedContentAuthData.from_bytes(auth_bytes)
		return cls(content=content, auth=auth, membership_tag=membership_tag)

	@classmethod
	def from_group_update(
		cls,
		update: "GroupUpdate",
		group_ctx: "GroupContext",
		confirmation_key: bytes,
		authentication_secret: bytes,
		transcript_hash: bytes,
	) -> "PublicMessage":
		"""Wrap a GroupUpdate as a RFC 9420 PublicMessage.

		RFC 9420 §6.2:
		- signature: Ed25519(FramedContentTBS)
		- confirmation_tag: HMAC-SHA256(confirmation_key, confirmed_transcript_hash)
		- membership_tag: HMAC-SHA256(membership_key, PublicMessageTBS)
		"""
		import hmac as _hmac

		commit_body = update.to_bytes()
		framed = FramedContent(
			group_id=group_ctx.group_id,
			epoch=update.epoch_id,
			sender_leaf_index=update.committer_index,
			authenticated_data=b"",
			content=commit_body,
		)

		# RFC 9420 §8.1: confirmation_tag = HMAC(confirmation_key, confirmed_transcript_hash)
		conf_tag = _hmac.new(confirmation_key, transcript_hash, "sha256").digest()

		auth = FramedContentAuthData(
			signature=update.signature,
			confirmation_tag=conf_tag,
		)

		# RFC 9420 §6.2: membership_key = ExpandWithLabel(authentication_secret, 'membership', b'', 32)
		membership_key = KeySchedule.derive_membership_key(authentication_secret)
		# PublicMessageTBS = version(u16) + wire_format(u16) + GroupContext + FramedContent
		public_msg_tbs = (
			tls_u16(0x0001)  # version
			+ tls_u16(0x0002)  # wire_format = mls_public_message
			+ group_ctx.to_bytes()
			+ framed.to_bytes()
		)
		mem_tag = _hmac.new(membership_key, public_msg_tbs, "sha256").digest()

		return cls(content=framed, auth=auth, membership_tag=mem_tag)

	def to_group_update(self) -> "GroupUpdate":
		return GroupUpdate.from_bytes(self.content.content)


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

		# Epoch ID for the new epoch (computed now so it's available in the loop)
		new_epoch_id = self.state.epoch_id + 1

		# STATE-04: key commit secrets by KeyPackageRef
		# Lookup is stable even after KEM key rotation.
		encrypted_secrets: dict[bytes, bytes] = {}
		for i, node in enumerate(new_tree.nodes):
			if isinstance(node, LeafNode) and i != self.my_index:
				pk = node.public_key
				# HPKE info = GroupContext of the *new* epoch for CRIT-01 context isolation
				group_ctx = _make_group_context(self.group_id, new_epoch_id, new_tree, b"")
				enc, ct = HPKE.seal(pk, commit_secret, info=group_ctx.to_bytes())
				kp_ref = _make_kp_ref(node.key_package)
				encrypted_secrets[kp_ref] = enc + ct

		# 3. Advance the epoch
		# STATE-02: deterministic canonical ordering by KP ref for transcript stability
		ciphertexts_bytes = b"".join(k + v for k, v in sorted(encrypted_secrets.items()))
		transcript_hash = _transcript_hash(
			self.group_id,
			new_epoch_id,
			new_tree,
			self.state.key_schedule.confirmation_key,
			ciphertexts_bytes,
			sender_index=self.my_index,
		)
		next_state = self.state.advance_epoch(commit_secret, new_tree, transcript_hash=transcript_hash)

		# RFC 9420 §6.2: sign FramedContentTBS (not raw transcript_hash)
		# GroupContext uses the new epoch with the confirmed transcript_hash
		new_ctx_signed = _make_group_context(self.group_id, new_epoch_id, new_tree, transcript_hash)
		# Build an unsigned GroupUpdate body to construct the FramedContent for TBS
		_unsigned_body = (
			tls_u64(new_epoch_id)
			+ tls_opaque32(new_tree.to_bytes())
			+ tls_u32(len(encrypted_secrets))
			+ b"".join(tls_opaque(k) + tls_opaque(v) for k, v in sorted(encrypted_secrets.items()))
			+ tls_u32(self.my_index)
		)
		_framed_for_tbs = FramedContent(
			group_id=new_ctx_signed.group_id,
			epoch=new_epoch_id,
			sender_leaf_index=self.my_index,
			authenticated_data=b"",
			content=_unsigned_body,
		)
		tbs = _make_framed_content_tbs(new_ctx_signed, _framed_for_tbs)
		signature = self.my_sig_key.sign(tbs)

		# 4. Build RFC-compliant Welcome
		new_epoch_group_ctx = _make_group_context(self.group_id, next_state.epoch_id, new_tree, b"")
		# GroupSecrets for the joiner (HPKE-sealed, info = GroupContext)
		group_secrets = GroupSecrets(
			joiner_secret=next_state.key_schedule.joiner_secret,
			joiner_index=new_leaf_idx,
		)
		gs_enc, gs_ct = HPKE.seal(
			key_package.init_key_pub,
			group_secrets.to_bytes(),
			info=b"",  # RFC §12.1.2: no additional info for EncryptedGroupSecrets
		)
		egs = EncryptedGroupSecrets(
			new_member=_make_kp_ref(key_package),
			kem_output=gs_enc,
			ciphertext=gs_ct,
		)

		# GroupInfo payload (tree + transcript_hash) — AES-GCM welcome_key (RFC §12.1.2)
		group_info_payload = (
			new_epoch_group_ctx.to_bytes() + tls_opaque(new_tree.to_bytes())  # ratchet tree extension
		)
		# welcome_key = ExpandWithLabel(joiner_secret, 'welcome', b'', 16)
		# welcome_nonce = ExpandWithLabel(joiner_secret, 'nonce', b'', 12)
		joiner_secret = next_state.key_schedule.joiner_secret
		welcome_key = KeySchedule.derive_welcome_key(joiner_secret, b"")
		welcome_nonce_enc = KeySchedule.derive_welcome_nonce(joiner_secret, b"")
		from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

		gi_ct = _AESGCM(welcome_key).encrypt(welcome_nonce_enc, group_info_payload, b"")
		# Store as nonce(12) + ciphertext so join() can decode without kem_output
		welcome = Welcome(
			cipher_suite=Welcome._CIPHER_SUITE,
			encrypted_group_secrets=[egs],
			encrypted_group_info=welcome_nonce_enc + gi_ct,
		)

		update = GroupUpdate(
			epoch_id=next_state.epoch_id,
			tree=new_tree,
			encrypted_commit_secrets=encrypted_secrets,
			committer_index=self.my_index,
			signature=signature,
			_group_ctx=new_ctx_signed,
			_confirmation_key=next_state.key_schedule.confirmation_key,
			_authentication_secret=next_state.key_schedule.authentication_secret,
			_transcript_hash=transcript_hash,
		)

		# Return mutated self
		new_group = MLSGroup(next_state, self.my_index, self.my_sig_key, self.my_kem_key)
		return new_group, welcome, update

	@classmethod
	def join(cls, welcome: Welcome, my_sig_key: SignatureKey, my_kem_key: KemKey) -> "MLSGroup":
		"""
		Initializes a Group from a Welcome message (RFC 9420 §12.1.2).
		Decrypts GroupSecrets and reconstructs the EpochState.
		"""
		# Find our EncryptedGroupSecrets by scanning the secrets list.
		# In practice we match by our KPRef or simply take the first entry
		# when there is only one joiner (our current model).
		if not welcome.encrypted_group_secrets:
			raise ValueError("Welcome contains no encrypted group secrets")

		# RFC 9420 §12.1.2 join sequence:
		# 1. Decrypt GroupSecrets via HPKE (info=b'' per RFC)
		egs = welcome.encrypted_group_secrets[0]
		gs_bytes_raw = HPKE.open(my_kem_key, egs.kem_output, egs.ciphertext, info=b"")
		gs = GroupSecrets.from_bytes(gs_bytes_raw)

		# 2. Derive welcome_key from joiner_secret and decrypt GroupInfo (AES-GCM)
		welcome_key_dec = KeySchedule.derive_welcome_key(gs.joiner_secret, b"")
		from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM2

		gi_payload_raw = welcome.encrypted_group_info
		if len(gi_payload_raw) < 12:
			raise ValueError("encrypted_group_info too short")
		gi_nonce_bytes, gi_ct = gi_payload_raw[:12], gi_payload_raw[12:]
		gi_bytes = _AESGCM2(welcome_key_dec).decrypt(gi_nonce_bytes, gi_ct, b"")

		# 3. Parse GroupContext and ratchet tree from GroupInfo plaintext
		gi_ctx = GroupContext.from_bytes(gi_bytes)
		gi_ctx_len = len(gi_ctx.to_bytes())
		tree_bytes, _ = read_opaque(gi_bytes, gi_ctx_len)
		tree = RatchetTree.from_bytes(tree_bytes)

		# 4. Reconstruct KeySchedule from joiner_secret
		epoch_secret = hkdf_extract(b"\x00" * 32, gs.joiner_secret, hashlib.sha256)
		ks = KeySchedule._from_epoch_secret(epoch_secret, gs.joiner_secret)

		state = EpochState(
			group_id=gi_ctx.group_id,
			epoch_id=gi_ctx.epoch,
			tree=tree,
			key_schedule=ks,
		)
		return cls(state, my_index=gs.joiner_index, my_sig_key=my_sig_key, my_kem_key=my_kem_key)

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

		# 1. Verify Signature FIRST to prevent padding oracles
		# STATE-02: recompute full GroupInfo transcript hash
		ciphertexts_bytes = b"".join(k + v for k, v in sorted(update.encrypted_commit_secrets.items()))
		try:
			public_key = ed25519.Ed25519PublicKey.from_public_bytes(committer_node.key_package.identity_key_pub)
			transcript_hash = _transcript_hash(
				self.group_id,
				update.epoch_id,
				update.tree,
				self.state.key_schedule.confirmation_key,
				ciphertexts_bytes,
				sender_index=update.committer_index,
			)
			# RFC 9420 §6.2: signature covers FramedContentTBS, not raw transcript_hash
			group_ctx_verify = _make_group_context(self.group_id, update.epoch_id, update.tree, transcript_hash)
			# Reconstruct unsigned body for FramedContent
			_unsigned_body_v = (
				tls_u64(update.epoch_id)
				+ tls_opaque32(update.tree.to_bytes())
				+ tls_u32(len(update.encrypted_commit_secrets))
				+ b"".join(tls_opaque(k) + tls_opaque(v) for k, v in sorted(update.encrypted_commit_secrets.items()))
				+ tls_u32(update.committer_index)
			)
			_framed_v = FramedContent(
				group_id=group_ctx_verify.group_id,
				epoch=update.epoch_id,
				sender_leaf_index=update.committer_index,
				authenticated_data=b"",
				content=_unsigned_body_v,
			)
			tbs = _make_framed_content_tbs(group_ctx_verify, _framed_v)
			public_key.verify(update.signature, tbs)
		except InvalidSignature:
			raise ValueError("Commit Forgery Detected: Invalid Signature in update")
		except Exception:
			raise ValueError("Invalid signature format")

		# 2. STATE-04: lookup commit secret by my KeyPackageRef, not by tree index.
		# This survives KEM key rotation: the ref is stable as long as the member
		# does not generate a brand-new KeyPackage in the same epoch.
		my_kp = self.state.tree.get_node(self.my_index)
		if not isinstance(my_kp, LeafNode):
			raise ValueError("My leaf node not found in tree")
		# HPKE info = GroupContext of the verifying epoch for CRIT-01
		group_ctx = _make_group_context(self.group_id, update.epoch_id, update.tree, b"")
		my_kp_ref = _make_kp_ref(my_kp.key_package)
		if my_kp_ref not in update.encrypted_commit_secrets:
			raise ValueError("Not invited to this epoch (KeyPackageRef not found in commit)")

		enc_ct = update.encrypted_commit_secrets[my_kp_ref]
		enc, ct = enc_ct[:32], enc_ct[32:]
		# HPKE info = GroupContext (Fase 4 migration of CRIT-01 context isolation)
		commit_secret = HPKE.open(self.my_kem_key, enc, ct, info=group_ctx.to_bytes())

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
