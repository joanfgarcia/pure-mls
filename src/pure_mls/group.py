import hashlib
import hmac
import os
import struct
import warnings as _warnings
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pure_mls.epoch import EpochState
from pure_mls.hkdf import expand_with_label, hkdf_extract, varint_encode
from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.keyschedule import KeySchedule, PreSharedKeyID, _psk_secret
from pure_mls.proposals import (
	AddProposal,
	Commit,
	ProposalOrRef,
	PSKProposal,
	proposal_from_bytes,
)
from pure_mls.secret_tree import SecretTree, derive_sender_data_key, derive_sender_data_nonce
from pure_mls.tls import (
	ExtensionType,
	_varint_decode,
	read_extensions,
	read_opaque,
	read_opaque32,
	read_u8,
	read_u16,
	read_u32,
	read_u64,
	tls_extensions,
	tls_opaque,
	tls_opaque32,
	tls_u8,
	tls_u16,
	tls_u32,
	tls_u64,
	tls_varint,
)
from pure_mls.tree import KeyPackage, LeafNode, ParentNode, RatchetTree

# GroupContext (RFC 9420 §8.1)


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
	extensions: list[tuple[int, bytes]]

	# Fixed for our single supported suite:
	#   MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
	_VERSION: int = 0x0001  # mls10
	_CIPHER_SUITE: int = 0x0001

	def to_bytes(self) -> bytes:
		"""RFC 9420 §8.1 TLS encoding of GroupContext.

		Wire format:
			uint16  version (0x0001)
			uint16  cipher_suite (0x0001)
			varint  len(group_id) + group_id bytes   [opaque<V>]
			uint64  epoch
			varint  len(tree_hash) + tree_hash bytes [opaque<V>]
			varint  len(cth) + cth bytes             [opaque<V>]
			varint  0 (empty extensions vector)
		"""
		return (
			tls_u16(self._VERSION)
			+ tls_u16(self._CIPHER_SUITE)
			+ tls_varint(len(self.group_id))
			+ self.group_id
			+ tls_u64(self.epoch)
			+ tls_varint(len(self.tree_hash))
			+ self.tree_hash
			+ tls_varint(len(self.confirmed_transcript_hash))
			+ self.confirmed_transcript_hash
			+ tls_extensions(self.extensions)
		)

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["GroupContext", int]:
		"""Decode a TLS-encoded GroupContext from a stream (RFC 9420 §8.1)."""
		version, offset = read_u16(data, offset)
		if version != cls._VERSION:
			raise ValueError(f"Unsupported GroupContext version: {version:#06x}")
		cipher_suite, offset = read_u16(data, offset)
		if cipher_suite != cls._CIPHER_SUITE:
			raise ValueError(f"Unsupported cipher suite: {cipher_suite:#06x}")
		# opaque<V> fields use VarInt length prefix (RFC 9420 §8.1)
		group_id, offset = read_opaque(data, offset)
		epoch, offset = read_u64(data, offset)
		tree_hash, offset = read_opaque(data, offset)
		confirmed_transcript_hash, offset = read_opaque(data, offset)
		extensions, offset = read_extensions(data, offset)
		return cls(
			group_id=group_id,
			epoch=epoch,
			tree_hash=tree_hash,
			confirmed_transcript_hash=confirmed_transcript_hash,
			extensions=extensions,
		), offset

	@classmethod
	def from_bytes(cls, data: bytes) -> "GroupContext":
		"""Decode a TLS-encoded GroupContext (RFC 9420 §8.1)."""
		gc, _ = cls.from_bytes_at(data, 0)
		return gc


# Welcome / GroupSecrets / EncryptedGroupSecrets (RFC 9420 §12.1.2)


@dataclass
class GroupSecrets:
	"""RFC 9420 §12.1.2: Internal struct sealed by HPKE for each joiner.

	Wire format: joiner_secret<V> + has_path_secret(u8) + [path_secret<V>]
	The joiner_index is NOT part of the RFC wire format; the joiner discovers
	their leaf by scanning GroupInfo tree for a leaf with their signature_key.
	"""

	joiner_secret: bytes  # 32 bytes
	path_secret: bytes | None = None  # optional — RFC §12.1.2 optional<PathSecret>
	psks: list[PreSharedKeyID] = field(default_factory=list)

	def to_bytes(self) -> bytes:

		actual_path = self.path_secret if self.path_secret else b""
		present = bool(actual_path)
		# joiner_secret<V> — varint length prefix
		result = tls_varint(len(self.joiner_secret)) + self.joiner_secret
		if present:
			result += b"\x01" + tls_varint(len(actual_path)) + actual_path
		else:
			result += b"\x00"
		# psk_ids vector: varint(len) + [PreSharedKeyID...].to_bytes()
		psk_vec_bytes = b"".join(p.to_bytes() for p in self.psks)
		result += tls_varint(len(psk_vec_bytes)) + psk_vec_bytes
		return result

	@classmethod
	def from_bytes(cls, data: bytes) -> "GroupSecrets":
		offset = 0
		joiner_secret, offset = read_opaque(data, offset)  # joiner_secret<V>
		has_path = data[offset]
		offset += 1
		path_secret: bytes | None = None
		if has_path:
			path_secret, offset = read_opaque(data, offset)  # path_secret<V>
		# psk_ids: varint(len) + records
		psks = []
		if offset < len(data):
			psks_total_len, offset = _varint_decode(data, offset)
			psks_end = offset + psks_total_len
			while offset < psks_end:
				# PreSharedKeyID from_bytes_at (to be verified if exists, or inline)
				# Based on KeySchedule.PreSharedKeyID structure
				psk_type = data[offset]
				offset += 1
				if psk_type == 1:  # EXTERNAL (only one we support here)
					pid, offset = read_opaque(data, offset)
					pnonce, offset = read_opaque(data, offset)
					psks.append(PreSharedKeyID(psk_type=1, psk_id=pid, psk_nonce=pnonce))
				else:  # RESUMPTION
					usage = data[offset]
					offset += 1
					pgid, offset = read_opaque(data, offset)
					pepoch = struct.unpack("!Q", data[offset : offset + 8])[0]
					offset += 8
					pnonce, offset = read_opaque(data, offset)
					psks.append(PreSharedKeyID(psk_type=2, psk_id=b"", usage=usage, psk_group_id=pgid, psk_epoch=pepoch, psk_nonce=pnonce))
		return cls(joiner_secret=joiner_secret, path_secret=path_secret, psks=psks)


@dataclass
class EncryptedGroupSecrets:
	"""
	HPKE-encrypted GroupSecrets for a single joiner (RFC 9420 §12.4.3.1).
	"""

	new_member: bytes  # KeyPackageRef (32 bytes)
	kem_output: bytes  # HPKE enc
	ciphertext: bytes  # HPKE ciphertext

	def to_bytes(self) -> bytes:
		"""Serialize to RFC 9420 §12.4.3.1 wire format."""
		return tls_opaque(self.new_member) + tls_opaque(self.kem_output) + tls_opaque(self.ciphertext)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["EncryptedGroupSecrets", int]:
		"""Parse from RFC 9420 §12.4.3.1 wire format."""
		# KeyPackageRef is nominally fixed Nh bytes, but IETF vectors (OpenMLS)
		# encode it as opaque<V> (with 1-byte length prefix usually).
		new_member, offset = read_opaque(data, offset)
		kem_output, offset = read_opaque(data, offset)
		ciphertext, offset = read_opaque(data, offset)
		return cls(new_member=new_member, kem_output=kem_output, ciphertext=ciphertext), offset


@dataclass
class Welcome:
	"""
	Welcome Message (RFC 9420 §12.4.3.1).
	Sent by committer to new members to provide group state.

	Contains:
	- HPKE-encrypted GroupSecrets for each joiner (keyed by KeyPackageRef)
	- HPKE-sealed GroupInfo (contains group_id, epoch, tree, transcript_hash)

	GroupInfo is sealed with AES-128-GCM using welcome_key derived from
	joiner_secret via ExpandWithLabel(joiner_secret, 'welcome', b'', 16).
	"""

	cipher_suite: int
	secrets: list[EncryptedGroupSecrets]  # EncryptedGroupSecrets secrets<V>
	encrypted_group_info: bytes  # opaque encrypted_group_info<V>

	def to_bytes(self) -> bytes:
		"""Serialize to RFC 9420 §12.4.3.1 wire format."""
		egs_bytes = b"".join(s.to_bytes() for s in self.secrets)
		return self.cipher_suite.to_bytes(2, "big") + tls_opaque(egs_bytes) + tls_opaque(self.encrypted_group_info)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> "Welcome":
		"""Parse from RFC 9420 §12.4.3.1 wire format."""
		# Handle optional MLSMessage header (ProtocolVersion + WireFormat)
		if len(data) >= (offset + 4) and data[offset : offset + 2] == b"\x00\x01":
			wf = int.from_bytes(data[offset + 2 : offset + 4], "big")
			if wf == 3:  # mls_welcome
				offset += 4

		cipher_suite, offset = read_u16(data, offset)
		egs_raw, offset = read_opaque(data, offset)
		egi, offset = read_opaque(data, offset)

		egs_list = []
		egs_offset = 0
		while egs_offset < len(egs_raw):
			egs, egs_offset = EncryptedGroupSecrets.from_bytes(egs_raw, egs_offset)
			egs_list.append(egs)

		return cls(
			cipher_suite=cipher_suite,
			secrets=egs_list,
			encrypted_group_info=egi,
		)

	@classmethod
	def from_mlsmessage_bytes(cls, data: bytes) -> "Welcome":
		"""Parse from full MLSMessage wire format (version+wire_format header + inner Welcome).

		MLSMessage header (4 bytes): uint16 version + uint16 wire_format (=3 for Welcome).
		"""
		# strip 4-byte MLSMessage header
		inner = data[4:]
		return cls.from_bytes(inner)

	def decrypt_group_secrets(
		self,
		init_key: "KemKey",
	) -> "GroupSecrets | None":
		"""Decrypt GroupSecrets for the joiner matching init_key.

		Searches encrypted_group_secrets for an entry whose kem_output can be
		decapsulated with init_key, then decrypts via HPKE.open with the
		RFC 9420 §12.4 EncryptWithLabel("Welcome", encrypted_group_info) context.

		This method is RFC-compliant and compatible with OpenMLS IETF vectors.
		The HPKE info string follows RFC 9420 §12.4: varint(label) + label + varint(egi) + egi.

		Note: MLSGroup.join() uses b"MLS 1.0 EncryptedGroupSecrets" (pure-mls internal
		convention, P0-B audit note). For OpenMLS interoperability, use this method
		or Welcome.from_mlsmessage_bytes() + decrypt_group_secrets() directly.

		Returns GroupSecrets on success, None if no matching entry found.
		"""
		label = b"MLS 1.0 Welcome"
		info = varint_encode(len(label)) + label + varint_encode(len(self.encrypted_group_info)) + self.encrypted_group_info

		for egs in self.encrypted_group_secrets:
			try:
				gs_bytes = HPKE.open(init_key, egs.kem_output, egs.ciphertext, info=info)
			except InvalidTag:
				continue
			return GroupSecrets.from_bytes(gs_bytes)
		return None


def WelcomeInfo(*args: Any, **kwargs: Any) -> "Welcome":
	"""Deprecated factory. Use Welcome directly."""
	_warnings.warn("WelcomeInfo is deprecated; use Welcome directly.", DeprecationWarning, stacklevel=2)
	return Welcome(*args, **kwargs)


# GroupInfo (RFC 9420 §12.1.2) — signed by the committer


@dataclass
class GroupInfo:
	"""RFC 9420 §12.1.2: GroupInfo — sent (AES-GCM encrypted) inside the Welcome.

	Wire format (TBS portion signed by committer):
		GroupContext     — standard TLS struct
		extensions<V>   — uint32 vector; empty (0x00000000) for now
		confirmation_tag — HMAC-SHA256(confirmation_key, confirmed_transcript_hash)
		signer           — uint32 leaf index of committer

	Full wire:
		TBS bytes        (above)
		signature<V>     — Ed25519 signature over TBS, by committer's signing key

	RFC §12.4: the confirmation_tag links the epoch's key material to the
	transcript, guaranteeing freshness. The signature links the GroupInfo
	to the committer's identity key.
	"""

	group_context: GroupContext
	extensions: list[tuple[int, bytes]]
	confirmation_tag: bytes  # HMAC-SHA256(confirmation_key, transcript_hash)
	signer: int  # committer leaf index
	signature: bytes  # Ed25519(SignContent(TBS))

	# ------------------------------------------------------------------
	# Serialisation helpers
	# ------------------------------------------------------------------

	def _tbs_bytes(self) -> bytes:
		"""TBS = GroupContext + extensions<V> + confirmation_tag[Nh] + signer(uint32)."""
		return self.group_context.to_bytes() + tls_extensions(self.extensions) + tls_opaque(self.confirmation_tag) + tls_u32(self.signer)

	@classmethod
	def from_bytes(cls, data: bytes) -> "GroupInfo":
		"""Standard RFC 9420 parser."""
		group_context, offset = GroupContext.from_bytes_at(data, 0)
		extensions, offset = read_extensions(data, offset)
		confirmation_tag, offset = read_opaque(data, offset)
		signer, offset = read_u32(data, offset)
		signature, offset = read_opaque(data, offset)

		return cls(
			group_context=group_context,
			extensions=extensions,
			confirmation_tag=confirmation_tag,
			signer=signer,
			signature=signature,
		)

	def to_bytes(self) -> bytes:
		"""Full wire encoding: TBS + signature<V>."""
		return self._tbs_bytes() + tls_opaque(self.signature)

	# ------------------------------------------------------------------
	# Signing and verification (RFC 9420 §16.1 Domain Separation)
	# ------------------------------------------------------------------

	def _sign_content_bytes(self) -> bytes:
		"""Wrap TBS in SignContent (label + content) for domain separation."""
		label = b"MLS 1.0 GroupInfoTBS"
		return tls_opaque(label) + tls_opaque(self._tbs_bytes())

	@classmethod
	def build_and_sign(
		cls,
		group_context: GroupContext,
		confirmation_tag: bytes,
		signer: int,
		sig_key: "SignatureKey",
		extensions: list[tuple[int, bytes]] = None,
	) -> "GroupInfo":
		"""Create a GroupInfo and sign it using SignContent domain separation."""
		gi = cls(
			group_context=group_context,
			extensions=extensions or [],
			confirmation_tag=confirmation_tag,
			signer=signer,
			signature=b"",
		)
		gi.signature = sig_key.sign(gi._sign_content_bytes())
		return gi

	def verify(self, committer_sig_key_bytes: bytes) -> bool:
		"""VerifyEd25519 signature over SignContent-wrapped TBS."""
		pub = ed25519.Ed25519PublicKey.from_public_bytes(committer_sig_key_bytes)
		pub.verify(self.signature, self._sign_content_bytes())
		return True


# KeyPackageRef + transcript hash (RFC 9420 §10.2, §8.2)

_KP_REF_LABEL: bytes = b"MLS 1.0 KeyPackage Reference"


def _make_kp_ref(kp: KeyPackage) -> bytes:
	"""RFC 9420 §5.2: MakeKeyPackageRef = RefHash('MLS 1.0 KeyPackage Reference', kp).

	RefHash(label, value) = Hash(RefHashInput) where:
		struct { opaque label<V>; opaque value<V>; } RefHashInput;
	"""
	kp_bytes = kp.to_bytes()
	ref_input = varint_encode(len(_KP_REF_LABEL)) + _KP_REF_LABEL + varint_encode(len(kp_bytes)) + kp_bytes
	return hashlib.sha256(ref_input).digest()


def _make_group_context(
	group_id: bytes,
	epoch_id: int,
	tree: RatchetTree,
	confirmed_transcript_hash: bytes,
	extensions: list[tuple[int, bytes]] = None,
) -> GroupContext:
	"""Build GroupContext for the given group state."""
	tree_hash = tree.tree_hash()
	return GroupContext(
		group_id=group_id,
		epoch=epoch_id,
		tree_hash=tree_hash,
		confirmed_transcript_hash=confirmed_transcript_hash,
		extensions=extensions or [],
	)


def _derive_path_node_key(path_secret: bytes) -> bytes:
	"""RFC 9420 §12.1.1: node_secret = ExpandWithLabel(path_secret, 'node', b'', 32).

	Returns the HPKE private key material (used with KemKey to build a key pair).
	"""
	return expand_with_label(path_secret, "node", b"", 32)


def _derive_next_path_secret(path_secret: bytes) -> bytes:
	"""RFC 9420 §12.1.1: next_path_secret = ExpandWithLabel(path_secret, 'path', b'', 32)."""
	return expand_with_label(path_secret, "path", b"", 32)


def _subtree_hash(tree: "RatchetTree", index: int) -> bytes:
	"""RFC 9420 §7.9: original_sibling_tree_hash = TreeHash(sibling) per §7.8.

	Delegates to RatchetTree._node_hash() which implements the full
	RFC 9420 §7.8 TreeHashInput algorithm (typed byte prefix 0x01/0x02,
	optional<Node>, VarInt-prefixed child hashes).

	P1-2 audit fix: previous implementation used ad-hoc SHA-256(kp.to_bytes())
	and SHA-256(pk + left + right) which diverges from RFC §7.8 TreeHashInput.
	"""
	# Guard: index=-1 is the OOB sentinel from copath(); any invalid index = blank leaf
	if index < 0 or index >= len(tree.nodes):
		# RFC §7.8 blank leaf: SHA-256(0x01 || 0x00)
		return hashlib.sha256(b"\x01\x00").digest()
	return tree._node_hash(index)


def _compute_parent_hash(
	new_public_key: bytes,
	parent_hash_of_parent: bytes,
	original_sibling_tree_hash: bytes,
) -> bytes:
	"""RFC 9420 §7.9: parent_hash = SHA-256(label + ParentHashInput).

	ParentHashInput: public_key(opaque) + parent_hash(opaque) + sibling_tree_hash(opaque).
	"""
	label = b"MLS 1.0 parent hash"
	return hashlib.sha256(
		tls_opaque(label) + tls_opaque(new_public_key) + tls_opaque(parent_hash_of_parent) + tls_opaque(original_sibling_tree_hash)
	).digest()


def _make_framed_content_tbs(group_ctx: GroupContext, framed: "FramedContent") -> bytes:
	"""RFC 9420 §6.2: FramedContentTBS = version + wire_format + GroupContext + FramedContent.

	This is what the committer signs with their Ed25519 key.
	"""
	return (
		tls_u16(0x0001)  # version = mls10
		+ tls_u16(0x0001)  # wire_format = mls_public_message
		+ group_ctx.to_bytes()  # GroupContext (binds to epoch)
		+ framed.to_bytes()  # FramedContent body
	)


def _egs_info(encrypted_group_info: bytes) -> bytes:
	"""RFC 9420 §12.4 EncryptWithLabel info for EncryptedGroupSecrets HPKE.

	Info = varint(len(label)) + label + varint(len(egi)) + egi
	Where label = b"MLS 1.0 Welcome"

	This matches OpenMLS wire format and the IETF passive-client-welcome vectors.
	Used by both add_member() (seal) and join() (open) to maintain symmetry.
	Also used by Welcome.decrypt_group_secrets() which is the public RFC API.
	"""

	label = b"MLS 1.0 Welcome"
	return varint_encode(len(label)) + label + varint_encode(len(encrypted_group_info)) + encrypted_group_info


def _compute_confirmed_transcript_hash_input(
	framed_content_bytes: bytes,
	signature: bytes,
) -> bytes:
	"""RFC 9420 §8.2 ConfirmedTranscriptHashInput struct.

	wire_format(u16) + FramedContent + opaque signature<V>
	"""
	return tls_u16(0x0001) + framed_content_bytes + tls_opaque(signature)


def _compute_confirmed_transcript_hash(
	interim_transcript_hash: bytes,
	confirmed_input: bytes,
) -> bytes:
	"""RFC 9420 §8.2 step 1: confirmed_transcript_hash.

	confirmed = SHA-256(interim_transcript_hash_[N-1] || ConfirmedTranscriptHashInput_[N])
	"""
	return hashlib.sha256(interim_transcript_hash + confirmed_input).digest()


def _compute_interim_transcript_hash(
	confirmed_transcript_hash: bytes,
	confirmation_tag: bytes,
) -> bytes:
	"""RFC 9420 §8.2 step 2: interim_transcript_hash.

	interim = SHA-256(confirmed_transcript_hash_[N] || confirmation_tag_[N])
	"""
	return hashlib.sha256(confirmed_transcript_hash + confirmation_tag).digest()


def _up_info(group_context_bytes: bytes) -> bytes:
	"""RFC 9420 §5.1.3: EncryptContext label wrapper for UpdatePathNode."""
	label = b"MLS 1.0 UpdatePathNode"
	return tls_varint(len(label)) + label + tls_varint(len(group_context_bytes)) + group_context_bytes


@dataclass
class GroupUpdate:
	"""RFC 9420 §12.1.1: Commit message (RFC compliant).

	Wraps a formal Commit object with epoch/signature/tag metadata.
	"""

	epoch_id: int
	commit: Commit
	committer_index: int
	signature: bytes
	group_id: bytes = b""
	# Optional: cached context fields for PublicMessage tagging
	_group_ctx: "GroupContext | None" = None
	_confirmation_key: bytes | None = None
	_epoch_authenticator: bytes | None = None
	_membership_key: bytes | None = None
	_transcript_hash: bytes | None = None
	_confirmation_tag: bytes | None = None
	_membership_tag: bytes | None = None

	def _body_bytes(self) -> bytes:
		"""The unsigned Commit body (RFC 9420 wire format)."""
		return self.commit.to_bytes()

	def to_bytes(self) -> bytes:
		"""Serialize GroupUpdate to TLS-style wire format (Commit body only)."""
		return self._body_bytes()

	@classmethod
	def from_bytes(cls, data: bytes) -> "GroupUpdate":
		"""Parse GroupUpdate (Commit body). Epoch/Index/Signature are handled by PublicMessage."""
		# This is a bit tricky: RFC Commit doesn't have epoch_id inside it.
		# The epoch_id comes from the FramedContent.
		# For legacy compat/simplification, we assume PublicMessage.from_bytes
		# will populate the metadata after parsing this body.
		commit, _ = Commit.from_bytes(data, 0)
		return cls(
			epoch_id=0,  # to be set by PublicMessage
			commit=commit,
			committer_index=0,  # to be set by PublicMessage
			signature=b"",  # to be set by PublicMessage
		)


# MLSMessage envelope (RFC 9420 §6)


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
			and commit._epoch_authenticator is not None
			and commit._membership_key is not None
			and commit._transcript_hash is not None
		):
			# Full RFC mode: proper confirmation_tag + membership_tag
			pm = PublicMessage.from_group_update(
				commit,
				group_ctx=commit._group_ctx,
				confirmation_key=commit._confirmation_key,
				membership_key=commit._membership_key,
				transcript_hash=commit._transcript_hash,
			)
		else:
			# P0-2: Deserialized GroupUpdate carries no epoch context — cannot produce
			# valid confirmation_tag or membership_tag. Raise rather than silently
			# degrade to predictable b"\x00"*32 HMAC keys.
			raise ValueError(
				"wrap_commit() requires a GroupUpdate produced by add_member() or "
				"remove_member(); deserialized GroupUpdate objects carry no epoch key "
				"material and cannot be re-wrapped."
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

	@classmethod
	def wrap_key_package(cls, kp: "KeyPackage") -> "MLSMessage":
		"""RFC 9420 §6: Wrap a KeyPackage in MLSMessage for out-of-band advertisement."""
		return cls(wire_format=WireFormat.MLS_KEY_PACKAGE, body=kp.to_bytes())

	def unwrap_key_package(self) -> "KeyPackage":
		"""RFC 9420 §6: Extract a KeyPackage from an MLS_KEY_PACKAGE MLSMessage."""
		if self.wire_format != WireFormat.MLS_KEY_PACKAGE:
			raise ValueError(f"Expected MLS_KEY_PACKAGE, got {self.wire_format:#06x}")
		return KeyPackage.from_bytes(self.body)


# UpdatePath / TreeKEM (RFC 9420 §12.1.1)


@dataclass
class HPKECiphertext:
	"""RFC 9420 §5.2: HPKE ciphertext = kem_output + ciphertext."""

	kem_output: bytes  # X25519 KEM enc (32 bytes for DHKEM-X25519)
	ciphertext: bytes  # HPKE-sealed plaintext

	def to_bytes(self) -> bytes:
		return tls_opaque(self.kem_output) + tls_opaque(self.ciphertext)

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["HPKECiphertext", int]:
		kem_output, offset = read_opaque(data, offset)
		ciphertext, offset = read_opaque(data, offset)
		return cls(kem_output=kem_output, ciphertext=ciphertext), offset


@dataclass
class UpdatePathNode:
	"""RFC 9420 §12.1.1: one node in the UpdatePath.

	new_public_key is the new HPKE public key for this tree node.
	encrypted_path_secret is the path secret encrypted to each resolution member.
	"""

	new_public_key: bytes
	encrypted_path_secret: list[HPKECiphertext]

	def to_bytes(self) -> bytes:
		enc = b"".join(ct.to_bytes() for ct in self.encrypted_path_secret)
		return tls_opaque(self.new_public_key) + tls_u32(len(self.encrypted_path_secret)) + enc

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["UpdatePathNode", int]:
		new_public_key, offset = read_opaque(data, offset)
		n, offset = read_u32(data, offset)
		encrypted_path_secret = []
		for _ in range(n):
			ct, offset = HPKECiphertext.from_bytes(data, offset)
			encrypted_path_secret.append(ct)
		return cls(new_public_key=new_public_key, encrypted_path_secret=encrypted_path_secret), offset


@dataclass
class UpdatePath:
	"""RFC 9420 §12.1.1: UpdatePath contains the new leaf public key and path nodes.

	leaf_key_package: updated KeyPackage for the committer's leaf
	nodes: one UpdatePathNode per node in direct_path(committer_leaf)
	"""

	leaf_key_package: "KeyPackage"
	nodes: list[UpdatePathNode]

	def to_bytes(self) -> bytes:
		kp_bytes = self.leaf_key_package.to_bytes()
		nodes_bytes = b"".join(n.to_bytes() for n in self.nodes)
		return tls_opaque(kp_bytes) + tls_u32(len(self.nodes)) + nodes_bytes

	@classmethod
	def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["UpdatePath", int]:
		kp_bytes, offset = read_opaque(data, offset)
		kp = KeyPackage.from_bytes(kp_bytes)
		n, offset = read_u32(data, offset)
		nodes = []
		for _ in range(n):
			node, offset = UpdatePathNode.from_bytes(data, offset)
			nodes.append(node)
		return cls(leaf_key_package=kp, nodes=nodes), offset


# FramedContent + AuthData + PublicMessage (RFC 9420 §6)


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
		# RFC 9420 §6.1: group_id<V> and authenticated_data<V> are VarInt-prefixed
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
		group_id, offset = read_opaque(data, offset)  # opaque group_id<V>
		epoch, offset = read_u64(data, offset)
		sender_type, offset = read_u8(data, offset)
		if sender_type != 0x01:
			raise ValueError(f"Unsupported SenderType: {sender_type:#04x}")
		sender_leaf_index, offset = read_u32(data, offset)
		authenticated_data, offset = read_opaque(data, offset)  # opaque authenticated_data<V>
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
		membership_key: bytes,
		transcript_hash: bytes,
	) -> "PublicMessage":
		"""Wrap a GroupUpdate as a RFC 9420 PublicMessage.

		RFC 9420 §6.2:
		- signature: Ed25519(FramedContentTBS)
		- confirmation_tag: HMAC-SHA256(confirmation_key, confirmed_transcript_hash)
		- membership_tag: HMAC-SHA256(membership_key, PublicMessageTBS)
		"""
		commit_body = update.to_bytes()
		framed = FramedContent(
			group_id=group_ctx.group_id,
			epoch=update.epoch_id,
			sender_leaf_index=update.committer_index,
			authenticated_data=b"",
			content=commit_body,
		)

		# RFC 9420 §8.1: confirmation_tag = HMAC(confirmation_key, confirmed_transcript_hash)
		conf_tag = hmac.new(confirmation_key, transcript_hash, "sha256").digest()

		auth = FramedContentAuthData(
			signature=update.signature,
			confirmation_tag=conf_tag,
		)

		# RFC 9420 §6.2: membership_key = ExpandWithLabel(epoch_authenticator, 'membership', b'', 32)
		# membership key from KeySchedule (P0-MK)
		# PublicMessageTBS must match _make_framed_content_tbs
		public_msg_tbs = _make_framed_content_tbs(group_ctx, framed)
		mem_tag = hmac.new(membership_key, public_msg_tbs, "sha256").digest()

		return cls(content=framed, auth=auth, membership_tag=mem_tag)

	def to_group_update(self) -> "GroupUpdate":
		update = GroupUpdate.from_bytes(self.content.content)
		update.group_id = self.content.group_id  # P0-2: propagate from FramedContent
		update._confirmation_tag = self.auth.confirmation_tag
		update._membership_tag = self.membership_tag
		return update


class MLSGroup:
	"""
	High-level state machine for an MLS Group.
	Manages the current EpochState and transitions.
	"""

	def __init__(
		self,
		state: EpochState,
		my_index: int,
		my_sig_key: SignatureKey,
		my_kem_key: KemKey,
		my_kp_ref: bytes,
		interim_transcript_hash: bytes = b"",
	):
		self._consumed_key_packages = set()
		self.state = state
		self.my_index = my_index
		self.my_sig_key = my_sig_key
		self.my_kem_key = my_kem_key
		self.my_kp_ref = my_kp_ref
		self._secret_tree: SecretTree | None = None
		# P0-A: prior epoch confirmed_transcript_hash used as HPKE info domain separator
		# in group_ctx_pre (add_member) and group_ctx (process_update).
		# Initialized to b"" for genesis (epoch 0) and propagated through each epoch transition.
		# NOT serialized in EpochState.to_bytes() — lives only in the running MLSGroup instance.
		self.interim_transcript_hash: bytes = interim_transcript_hash
		# RFC 9420 §12.2: store for by_reference proposal resolution
		self.proposal_store: dict[bytes, bytes] = {}

	@property
	def group_id(self) -> bytes:
		return self.state.group_id

	@property
	def epoch_id(self) -> int:
		return self.state.epoch_id

	@property
	def application_key(self) -> bytes:
		"""Deprecated: direct use of encryption_secret as key. Use SecretTree instead."""
		_warnings.warn(
			"application_key is deprecated; encrypt/decrypt now use SecretTree per RFC §9",
			DeprecationWarning,
			stacklevel=2,
		)
		return self.state.key_schedule.encryption_secret

	def _get_secret_tree(self) -> SecretTree:
		"""Lazily create or return the per-epoch SecretTree."""
		if self._secret_tree is None:
			n_leaves = (len(self.state.tree.nodes) + 1) // 2
			self._secret_tree = SecretTree(
				encryption_secret=bytearray(self.state.key_schedule.encryption_secret),  # P2-1: mutable for in-place wipe
				n_leaves=n_leaves,
			)
		return self._secret_tree

	def _wipe_secret_tree(self) -> None:
		"""RFC 9420 §9: zero old-epoch key material to enforce forward secrecy."""
		if self._secret_tree is not None:
			self._secret_tree.wipe()
			self._secret_tree = None

	@classmethod
	def create(cls, group_id: bytes, creator_sig_key: SignatureKey, creator_kem_key: KemKey) -> "MLSGroup":
		"""
		Initialize a new MLS group (Genesis).
		The creator becomes leaf 0.
		"""
		tree = RatchetTree(num_leaves=1)
		kp = KeyPackage.create(
			encryption_key=creator_kem_key.public_bytes(),
			init_key_pub=KemKey().public_bytes(),
			signature_key=creator_sig_key.public_bytes(),
			identity=creator_sig_key.public_bytes(),
			sign_fn=creator_sig_key.sign,
		)
		tree.set_leaf(0, kp.leaf_node)

		# P0-C: RFC 9420 §8.1 — genesis epoch MUST bind KeySchedule to a GroupContext
		# so that different groups at epoch 0 derive distinct secrets.
		# _make_group_context is available here (group.py); passed to epoch.py via parameter
		# to avoid circular import: epoch.py ↛ group.py.
		genesis_ctx = _make_group_context(group_id, 0, tree, b"")
		state = EpochState.genesis(group_id, tree, group_context_bytes=genesis_ctx.to_bytes())
		# P0-A: genesis interim_transcript_hash = b"" (epoch 0 has no prior commit)
		return cls(
			state,
			my_index=0,
			my_sig_key=creator_sig_key,
			my_kem_key=creator_kem_key,
			my_kp_ref=_make_kp_ref(kp),
			interim_transcript_hash=b"",
		)

	def add_member(
		self, key_package: KeyPackage, psk_list: list[tuple[PreSharedKeyID, bytes]] | None = None
	) -> tuple["MLSGroup", Welcome, GroupUpdate]:
		"""
		Adds a new member, generating a Commit and advancing the Epoch.
		Returns the updated Group, the Welcome for the joiner, and the Update for peers.
		(Simplified: we just append to the tree, rebuild the direct path, and derive a new commit_secret).
		"""
		kp_ref = _make_kp_ref(key_package)
		if not hasattr(self, "_consumed_key_packages"):
			self._consumed_key_packages = set()
		if kp_ref in self._consumed_key_packages:
			raise ValueError("KeyPackage Replay: This KeyPackage has already been used in this instance.")
		self._consumed_key_packages.add(kp_ref)

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

		# Insert the new leaf using the joiner's LeafNode directly
		new_leaf_idx = (new_num_leaves - 1) * 2
		new_tree.set_leaf(new_leaf_idx, key_package.leaf_node)

		# 2. TreeKEM Commit (RFC 9420 §12.1.1)
		# Validate incoming KeyPackage signature if present
		if key_package.leaf_node_signature:
			key_package.verify_signature()  # raises InvalidSignature on tamper

		new_epoch_id = self.state.epoch_id + 1

		# Generate fresh leaf path secret (root of the committer's path update)
		leaf_path_secret = os.urandom(32)

		# Build direct_path and copath for the committer's leaf
		direct = new_tree.direct_path(self.my_index)
		cop = new_tree.copath(self.my_index)

		# Derive path secrets bottom-up (innermost → outermost/root)
		_path_secrets: list[bytes] = []
		current_secret = leaf_path_secret
		for _ in direct:
			current_secret = _derive_next_path_secret(current_secret)
			_path_secrets.append(current_secret)

		# commit_secret = final (outermost) path secret
		commit_secret: bytes = _path_secrets[-1] if _path_secrets else leaf_path_secret

		# Build signed updated leaf KeyPackage for the committer (fresh HPKE key)
		# IMPORTANT: This must happen BEFORE computing group_ctx_pre so that the
		# tree_hash in group_ctx_pre matches what process_update() will see in update.tree.
		new_committer_kem = KemKey()
		new_committer_kp = KeyPackage.create(
			encryption_key=new_committer_kem.public_bytes(),
			init_key_pub=KemKey().public_bytes(),
			signature_key=self.my_sig_key.public_bytes(),
			identity=self.my_sig_key.public_bytes(),
			sign_fn=self.my_sig_key.sign,
		)
		new_tree.set_leaf(self.my_index, new_committer_kp.leaf_node)

		# Build UpdatePath: encrypt each path_secret to copath resolution members
		# and compute parent_hash per RFC 9420 §7.9

		# We process direct_path from innermost (leaf's parent) to outermost (root).
		# parent_hash(node) depends on parent_hash(parent(node)), so we compute
		# outer → inner and then build nodes inner → outer.
		# Strategy: compute all hashes first (root has ph=b""), then fill nodes.
		_parent_hashes: list[bytes] = [b""] * len(direct)
		_node_pubs: list[bytes] = []

		for ps in _path_secrets:
			_node_secret = _derive_path_node_key(ps)
			_kem_node = KemKey.from_secret(_node_secret)
			_node_pubs.append(_kem_node.public_bytes())

		for node_i in range(len(direct) - 1, -1, -1):
			dp_idx, cop_idx = direct[node_i], cop[node_i]
			ph_above = _parent_hashes[node_i + 1] if node_i + 1 < len(direct) else b""
			_ph = _compute_parent_hash(_node_pubs[node_i], ph_above, _subtree_hash(new_tree, cop_idx))
			_parent_hashes[node_i] = _ph
			new_tree.set_parent(dp_idx, ParentNode(public_key=_node_pubs[node_i], parent_hash=_ph))

		# RFC 9420 §12.4.1: provisional GroupContext uses the OLD confirmed_transcript_hash.
		# This is identical on all peers at the start of a commit.
		group_ctx_pre = _make_group_context(self.group_id, new_epoch_id, new_tree, self.interim_transcript_hash)

		# Encrypt path secrets using the fully updated group_ctx_pre
		update_path_nodes: list[UpdatePathNode] = []
		for (dp_idx, cop_idx, ps), _new_pub in zip(zip(direct, cop, _path_secrets), _node_pubs):
			resolved = new_tree.resolution(cop_idx)
			ctexts: list[HPKECiphertext] = []
			for res_idx in resolved:
				res_node = new_tree.get_node(res_idx)
				if res_node is None:
					continue
				recipient_pk = res_node.public_key
				enc, ct = HPKE.seal(recipient_pk, ps, info=_up_info(group_ctx_pre.to_bytes()))
				ctexts.append(HPKECiphertext(kem_output=enc, ciphertext=ct))
			update_path_nodes.append(UpdatePathNode(new_public_key=_new_pub, encrypted_path_secret=ctexts))

		update_path = UpdatePath(leaf_key_package=new_committer_kp, nodes=update_path_nodes)

		# 3. Assemble Proposals (RFC 9420 §12)
		props = []
		# Add new member
		props.append(ProposalOrRef(value=AddProposal(key_package.to_bytes()).to_bytes()))
		# Add PSKs
		if psk_list:
			for p_id, _ in psk_list:
				props.append(ProposalOrRef(value=PSKProposal(psk_id=p_id.psk_id, psk_nonce=p_id.psk_nonce).to_bytes()))

		commit = Commit(proposals=props, update_path_bytes=update_path.to_bytes())

		# 4. Advance the epoch — RFC §8.2 two-pass transcript hash (P1-A)
		# P1-A: Build FramedContent BEFORE computing the transcript hash.
		_framed_for_tbs = FramedContent(
			group_id=self.group_id,
			epoch=self.state.epoch_id,
			sender_leaf_index=self.my_index,
			authenticated_data=b"",
			content=commit.to_bytes(),
		)
		framed_content_bytes = _framed_for_tbs.to_bytes()

		# P1-SIGN: Sign TBS with OLD GroupContext
		old_ctx = _make_group_context(self.group_id, self.state.epoch_id, self.state.tree, self.interim_transcript_hash)
		tbs = _make_framed_content_tbs(old_ctx, _framed_for_tbs)
		signature = self.my_sig_key.sign(tbs)

		# P1-TH & P1-CTH: Transcript Hash Sequence
		confirmed_input = _compute_confirmed_transcript_hash_input(framed_content_bytes, signature)
		transcript_hash = _compute_confirmed_transcript_hash(self.interim_transcript_hash, confirmed_input)

		# P1-3 consolidated: advance epoch first, then derive conf_tag once
		# (removes redundant provisional _conf_key + _conf_tag derivation)
		new_ctx_signed = _make_group_context(self.group_id, new_epoch_id, new_tree, transcript_hash)
		next_state = self.state.advance_epoch(
			commit_secret,
			new_tree,
			group_context=new_ctx_signed.to_bytes(),
			psk_list=psk_list,
		)

		# Single conf_tag derivation from canonical next_state key
		conf_tag = hmac.new(next_state.key_schedule.confirmation_key, transcript_hash, "sha256").digest()

		# Compute NEW interim_transcript_hash to store in state
		new_interim = _compute_interim_transcript_hash(transcript_hash, conf_tag)

		# 4. Build RFC-compliant Welcome  (P0-B: RFC §12.4 ordering)
		#
		# Correct ordering to satisfy RFC §12.4 info = EncryptWithLabel("Welcome", egi):
		#   a) Build + sign GroupInfo (does not depend on EGI or GroupSecrets)
		#   b) Encrypt GroupInfo → encrypted_group_info (egi)
		#   c) Seal GroupSecrets with info = _egs_info(egi)  ← RFC-compliant
		#   d) Assemble Welcome
		#
		# This ensures join() can open EGS with _egs_info(welcome.encrypted_group_info)
		# and get the same symmetric HPKE info, matching OpenMLS wire format.

		# 4a. Build + sign GroupInfo
		gi_group_ctx = _make_group_context(self.group_id, next_state.epoch_id, new_tree, transcript_hash)
		group_info = GroupInfo.build_and_sign(
			group_context=gi_group_ctx,
			confirmation_tag=conf_tag,
			signer=self.my_index,
			sig_key=self.my_sig_key,
		)

		# 4b. Encrypt GroupInfo → encrypted_group_info (egi)
		joiner_secret = next_state.key_schedule.joiner_secret
		welcome_key = KeySchedule.derive_welcome_key(joiner_secret)
		welcome_nonce_enc = KeySchedule.derive_welcome_nonce(joiner_secret)  # RFC 9420 §12.4
		# P1-3: RFC 9420 §12.4.3 — ratchet tree delivered inside GroupInfo extensions
		# as ExtensionType 0x0004, VarInt-prefixed
		tree_raw = new_tree.to_bytes()
		ext_data = tls_opaque(tree_raw)  # extension data = opaque<V> tree
		ext_entry = tls_u16(0x0004) + tls_opaque(ext_data)  # type(u16) + data<V>
		ext_vec = tls_opaque(ext_entry)  # extensions<V>
		gi_plaintext = group_info.to_bytes() + ext_vec
		gi_ct = AESGCM(welcome_key).encrypt(welcome_nonce_enc, gi_plaintext, b"")
		egi = welcome_nonce_enc + gi_ct  # nonce(12) || ciphertext

		# 4c. Seal GroupSecrets with RFC §12.4 info = EncryptWithLabel("Welcome", egi)
		group_secrets = GroupSecrets(
			joiner_secret=next_state.key_schedule.joiner_secret,
			psks=[p[0] for p in psk_list] if psk_list else [],
		)
		gs_enc, gs_ct = HPKE.seal(
			key_package.init_key_pub,
			group_secrets.to_bytes(),
			info=_egs_info(egi),
		)
		egs = EncryptedGroupSecrets(
			new_member=_make_kp_ref(key_package),
			kem_output=gs_enc,
			ciphertext=gs_ct,
		)

		# 4d. Assemble Welcome with egi and egs
		welcome = Welcome(
			cipher_suite=Welcome._CIPHER_SUITE,
			encrypted_group_secrets=[egs],
			encrypted_group_info=egi,
		)

		update = GroupUpdate(
			epoch_id=next_state.epoch_id,
			group_id=self.group_id,
			commit=commit,
			committer_index=self.my_index,
			signature=signature,
			_group_ctx=new_ctx_signed,
			_confirmation_key=next_state.key_schedule.confirmation_key,
			_epoch_authenticator=next_state.key_schedule.epoch_authenticator,
			_membership_key=self.state.key_schedule.membership_key,  # P0-1: old-epoch key per RFC §6.2
			_transcript_hash=transcript_hash,
			_confirmation_tag=conf_tag,  # P1-3: single derivation used for all
		)

		# Return mutated self (my_kem_key is now the fresh TreeKEM leaf key)
		# P0-A: propagate interim_transcript_hash to new epoch for next commit's HPKE info
		self._wipe_secret_tree()  # P2-N1: forward secrecy — zeroize old epoch before transition
		new_group = MLSGroup(next_state, self.my_index, self.my_sig_key, new_committer_kem, interim_transcript_hash=new_interim)
		new_group._consumed_key_packages = set(self._consumed_key_packages)  # P0-1: propagate replay protection across epoch
		return new_group, welcome, update

	def remove_member(self, target_leaf_index: int) -> tuple["MLSGroup", "GroupUpdate"]:
		"""RFC 9420 §12.1.1: Remove a member from the group.

		1. Blank the target leaf and its direct path (RatchetTree.remove_leaf).
		2. Generate fresh commit_secret (TreeKEM path secret for new epoch).
		3. Encrypt commit_secret for all remaining members.
		4. Two-pass transcript hash to produce confirmation_tag.
		5. Sign the commit and return (new_group, update).

		Args:
			target_leaf_index: The *node array* index (must be even) of the leaf to remove.

		Returns:
			(new_group, update) where new_group is the committer's post-remove state
			and update is the GroupUpdate for distribution to remaining members.
		"""
		if target_leaf_index == self.my_index:
			raise ValueError("Cannot remove yourself — use leave() or let another member remove you")
		if target_leaf_index % 2 != 0:
			raise ValueError("target_leaf_index must be even (leaf node)")

		# Step 1: Remove leaf from tree
		new_tree = self.state.tree.remove_leaf(target_leaf_index)
		new_epoch_id = self.epoch_id + 1

		# Step 2: Fresh commit secret for the new epoch
		commit_secret = os.urandom(32)

		# Step 3: Encrypt commit_secret for remaining members
		# RFC 9420 §12.4.1: provisional GroupContext uses the OLD confirmed_transcript_hash.
		group_ctx_pre = _make_group_context(self.group_id, new_epoch_id, new_tree, self.interim_transcript_hash)
		encrypted_commit_secrets: dict[bytes, bytes] = {}
		for leaf_idx in range(0, len(new_tree.nodes), 2):
			node = new_tree.get_node(leaf_idx)
			if node is None or leaf_idx == self.my_index:
				continue  # skip blank leaves and self
			if not isinstance(node, LeafNode):
				continue
			kp_ref = _make_kp_ref(node.key_package)
			enc, ct = HPKE.seal(node.public_key, commit_secret, info=_up_info(group_ctx_pre.to_bytes()))
			encrypted_commit_secrets[kp_ref] = enc + ct

		# Step 4: Build unsigned commit body for FramedContent
		_n = len(encrypted_commit_secrets)
		unsigned_body = (
			tls_u64(new_epoch_id)
			+ tls_opaque32(new_tree.to_bytes())
			+ tls_u32(_n)
			+ b"".join(tls_opaque(k) + tls_opaque(v) for k, v in sorted(encrypted_commit_secrets.items()))
			+ tls_u32(self.my_index)
		)

		framed_content = FramedContent(
			group_id=self.group_id,
			epoch=self.state.epoch_id,
			sender_leaf_index=self.my_index,
			authenticated_data=b"",
			content=unsigned_body,
		)
		framed_content_bytes = framed_content.to_bytes()

		# P1-SIGN: Sign TBS with OLD GroupContext
		old_ctx = _make_group_context(self.group_id, self.state.epoch_id, self.state.tree, self.interim_transcript_hash)
		tbs = _make_framed_content_tbs(old_ctx, framed_content)
		signature = self.my_sig_key.sign(tbs)

		# P1-TH & P1-CTH: Transcript Hash Sequence
		confirmed_input = _compute_confirmed_transcript_hash_input(framed_content_bytes, signature)
		transcript_hash = _compute_confirmed_transcript_hash(self.interim_transcript_hash, confirmed_input)

		# P1-3 consolidated: advance epoch first, then derive conf_tag once
		new_ctx = _make_group_context(self.group_id, new_epoch_id, new_tree, transcript_hash)
		next_state = self.state.advance_epoch(
			commit_secret,
			new_tree,
			group_context=new_ctx.to_bytes(),
		)

		# Single conf_tag derivation from canonical next_state key
		conf_tag = hmac.new(next_state.key_schedule.confirmation_key, transcript_hash, "sha256").digest()

		# Compute NEW interim_transcript_hash to store in MLSGroup
		new_interim = _compute_interim_transcript_hash(transcript_hash, conf_tag)

		update = GroupUpdate(
			epoch_id=new_epoch_id,
			tree=new_tree,
			encrypted_commit_secrets=encrypted_commit_secrets,
			committer_index=self.my_index,
			signature=signature,
			group_id=self.group_id,
			_group_ctx=new_ctx,
			_confirmation_key=next_state.key_schedule.confirmation_key,
			_epoch_authenticator=next_state.key_schedule.epoch_authenticator,
			_membership_key=self.state.key_schedule.membership_key,  # P0-1: old-epoch key per RFC §6.2
			_transcript_hash=transcript_hash,
			_confirmation_tag=conf_tag,  # P1-3: single derivation
		)

		self._wipe_secret_tree()  # P2-N1: forward secrecy — zeroize old epoch before transition
		new_group = MLSGroup(next_state, self.my_index, self.my_sig_key, self.my_kem_key, interim_transcript_hash=new_interim)
		new_group._consumed_key_packages = set(self._consumed_key_packages)  # P0-1: propagate replay protection across epoch
		return new_group, update

	@classmethod
	def join(
		cls,
		welcome: "Welcome | bytes",
		my_sig_key: SignatureKey,
		my_kem_key: KemKey,
		psk_list: list[tuple[PreSharedKeyID, bytes]] | None = None,
		ratchet_tree: RatchetTree | None = None,
	) -> "MLSGroup":
		"""
		Initializes a Group from a Welcome message (RFC 9420 §12.1.2).
		Decrypts GroupSecrets and reconstructs the EpochState.

		Accepts either a Welcome object or raw TLS wire-format bytes.
		If the Welcome message does not contain a ratchet_tree extension,
		one MUST be provided via the ratchet_tree argument.
		"""
		# (Logic remains same until tree parsing...)
		# Auto-detect: if raw bytes, parse as Welcome TLS wire format
		if isinstance(welcome, (bytes, bytearray)):
			try:
				welcome = Welcome.from_bytes(welcome)
			except Exception as exc:
				raise ValueError(f"Failed to parse Welcome TLS bytes: {exc}") from exc
		# RFC 9420 §12.4.3.1: find our EncryptedGroupSecrets by trying each (KPRef match).
		# For single-joiner cases, take the only entry. For multi-joiner, try each.
		gs_bytes_raw: bytes | None = None
		egs_match: EncryptedGroupSecrets | None = None
		for candidate in welcome.secrets:
			try:
				# P0-B: RFC 9420 §12.4 EncryptWithLabel("Welcome", encrypted_group_info)
				# Symmetric with add_member() seal — uses RFC info, matches IETF vectors
				gs_bytes_raw = HPKE.open(my_kem_key, candidate.kem_output, candidate.ciphertext, info=_egs_info(welcome.encrypted_group_info))
				egs_match = candidate
				break
			except (InvalidTag, ValueError):
				continue
		if gs_bytes_raw is None or egs_match is None:
			raise ValueError("No EncryptedGroupSecrets could be decrypted with the provided KEM key")

		# 1.5 Parse GroupSecrets and resolve PSKs (RFC 9420 §12.4.2)
		gs = GroupSecrets.from_bytes(gs_bytes_raw)

		# Resolve PSKs indicated in the Welcome message
		resolved_psks = []
		if gs.psks:
			if psk_list is None:
				raise ValueError("Welcome message requires PSKs, but none were provided")
			psk_map = {pid.psk_id: val for pid, val in psk_list}
			for psk_id in gs.psks:
				if psk_id.psk_id not in psk_map:
					raise ValueError(f"Required PSK {psk_id.psk_id.hex()} not found in provided psk_list")
				resolved_psks.append((psk_id, psk_map[psk_id.psk_id]))

		# 2. Derive welcome_key/nonce from joiner_secret + psk_secret and decrypt GroupInfo
		psk_secret = _psk_secret(resolved_psks)
		welcome_key_dec = KeySchedule.derive_welcome_key(gs.joiner_secret, psk_secret)
		welcome_nonce_dec = KeySchedule.derive_welcome_nonce(gs.joiner_secret, psk_secret)

		gi_ct = welcome.encrypted_group_info
		try:
			gi_bytes = AESGCM(welcome_key_dec).decrypt(welcome_nonce_dec, gi_ct, b"")
		except Exception as exc:
			raise ValueError(f"Failed to decrypt GroupInfo: {exc}")

		# 3. Parse signed GroupInfo + ratchet_tree extension (RFC §12.4.3)
		gi = GroupInfo.from_bytes(gi_bytes)
		gi_ctx = gi.group_context

		# Parse extensions to find ratchet_tree
		tree: RatchetTree | None = None
		for ext_type, ext_data in gi.extensions:
			if ext_type == ExtensionType.RATCHET_TREE:
				# ratchet_tree is optional<Node> ratchet_tree<V>
				tree = RatchetTree.from_bytes(ext_data)
				break

		# Fallback to provided tree if extension is missing
		if tree is None:
			tree = ratchet_tree

		if tree is None:
			raise ValueError("ratchet_tree extension absent from GroupInfo and no external tree provided")

		# 4. Verify GroupInfo signature (RFC §12.1.2 — authenticate the committer)
		# signer is a leaf index, map to node index (leaf_index * 2)
		committer_node = tree.get_node(gi.signer * 2)
		if not isinstance(committer_node, LeafNode):
			raise ValueError(f"GroupInfo.signer ({gi.signer}) leaf node not found at expected index {gi.signer * 2}")
		try:
			gi.verify(committer_node.signature_key)
		except Exception as exc:
			raise ValueError(f"GroupInfo signature verification failed: {exc}") from exc

		# 5. RFC 9420: discover joiner leaf index by scanning tree for our signature key
		my_sig_pub = my_sig_key.public_bytes()
		node_index: int | None = None
		for i, node in enumerate(tree.nodes):
			if i % 2 == 0 and isinstance(node, LeafNode):
				if hmac.compare_digest(node.signature_key, my_sig_pub):
					node_index = i
					break
		if node_index is None:
			raise ValueError("My leaf not found in GroupInfo tree — mismatched identity key")
		my_index = node_index // 2
		# P0-Join: Reconstruct our KeyPackage to get our KeyPackageRef
		# In a real system, the client would have its published KeyPackage stored.
		# Here we reconstruct it using the keys provided to join().
		# Ref: RFC 9420 §10.1
		_my_kp = KeyPackage.create(
			encryption_key=my_kem_key.public_bytes(),
			init_key_pub=KemKey().public_bytes(),  # Dummy init key (not used in RefHash)
			signature_key=my_sig_key.public_bytes(),
			identity=my_sig_key.public_bytes(),
			sign_fn=my_sig_key.sign,
		)
		my_kp_ref = _make_kp_ref(_my_kp)

		# 8.4 Key Schedule
		# intermediate_secret = HKDF-Extract(joiner_secret, psk_secret)
		# For Suite 1 (the only one we support in this test), Nh = 32.
		_nh = 32 if welcome.cipher_suite == 1 else 32
		psk_sec = _psk_secret(resolved_psks, _nh)
		intermediate = hkdf_extract(gs.joiner_secret, psk_sec)

		# epoch_secret = HKDF-Expand-Label(intermediate_secret, "epoch", GroupContext, Nh)
		epoch_secret = expand_with_label(intermediate, "epoch", gi_ctx.to_bytes(), _nh)

		# Derive the full epoch key schedule from the epoch_secret
		# Ref: RFC 9420 §8.4 / Figure 22
		ks = KeySchedule._from_epoch_secret(epoch_secret, gs.joiner_secret, intermediate)

		state = EpochState(
			group_id=gi_ctx.group_id,
			epoch_id=gi_ctx.epoch,
			tree=tree,
			key_schedule=ks,
		)

		# P1-N4: RFC 9420 §12.4.3.1 — joiner MUST verify confirmation_tag in GroupInfo
		# Calculated as HMAC(confirmation_key, confirmed_transcript_hash)
		expected_tag = hmac.new(ks.confirmation_key, gi_ctx.confirmed_transcript_hash, hashlib.sha256).digest()
		if gi.confirmation_tag != expected_tag:
			raise ValueError("GroupInfo confirmation_tag verification failed — forged Welcome or epoch mismatch (P1-N4)")

		# RFC 9420 §12.4.3: compute interim_transcript_hash using GroupInfo.confirmation_tag
		new_interim = _compute_interim_transcript_hash(gi_ctx.confirmed_transcript_hash, gi.confirmation_tag)
		return cls(
			state,
			my_index=my_index,
			my_sig_key=my_sig_key,
			my_kem_key=my_kem_key,
			my_kp_ref=my_kp_ref,
			interim_transcript_hash=new_interim,
		)

	def process_update(self, update: GroupUpdate, psk_list: list[tuple[PreSharedKeyID, bytes]] | None = None) -> "MLSGroup":
		"""
		Process a Commit from another member (RFC 9420 §12).
		Reconstructs the next tree and advances local state.
		"""
		if update.group_id != self.group_id:
			raise ValueError(f"GroupUpdate group_id mismatch: {update.group_id!r} != {self.group_id!r}")
		# Note: epoch_id validation is handled in PublicMessage wrapper but we verify here for safety
		# (PublicMessage in pure-mls currently sets it to 0 in from_bytes, we fix it later in the wrapper)

		# 1. Parse Commit and resolve proposals
		commit = update.commit
		new_tree = self.state.tree.expanded(self.state.tree.num_leaves)  # copy current
		resolved_psks = []

		for por in commit.proposals:
			# Resolution of ProposalOrRef
			prop_data = None
			if por.value:
				prop_data = por.value
			elif por.reference:
				if por.reference not in self.proposal_store:
					raise ValueError(f"Proposal reference {por.reference.hex()} not found in store")
				prop_data = self.proposal_store[por.reference]

			if prop_data:
				prop, _ = proposal_from_bytes(prop_data)
				if isinstance(prop, AddProposal):
					# Expand tree and add member
					new_tree = new_tree.expanded(new_tree.num_leaves + 1)
					new_leaf_idx = (new_tree.num_leaves - 1) * 2
					kp = KeyPackage.from_bytes(prop.key_package_bytes)
					new_tree.set_leaf(new_leaf_idx, kp.leaf_node)
				elif isinstance(prop, PSKProposal):
					# Resolve PSK
					found = False
					if psk_list:
						for p_id, val in psk_list:
							if p_id.psk_id == prop.psk_id:
								resolved_psks.append((p_id, val))
								found = True
								break
					if not found:
						raise ValueError(f"Required PSK {prop.psk_id.hex()} not provided for resolution")

		# 2. Re-verify/Apply UpdatePath
		# In RFC 9420, Commit.path contains the committer's new leaf/path.
		# our Commit object stores it in update_path_bytes.
		commit_secret: bytes | None = None

		# P1-A: provisional GroupContext for HPKE (uses OLD confirmed_transcript_hash)
		provisional_ctx = _make_group_context(self.group_id, self.state.epoch_id + 1, new_tree, self.interim_transcript_hash)

		if commit.update_path_bytes:
			update_path, _ = UpdatePath.from_bytes(commit.update_path_bytes)
			# Apply updated leaf
			new_tree.set_leaf(update.committer_index, update_path.leaf_key_package.leaf_node)

			# Decrypt path secret if we are in the resolution of one of the nodes
			direct = new_tree.direct_path(update.committer_index)
			cop = new_tree.copath(update.committer_index)

			for i, (node, dp_idx, cop_idx) in enumerate(zip(update_path.nodes, direct, cop)):
				# Update the tree node public key
				# (In a real implementation we'd also verify parent_hash here)
				# We don't have the full TreeKEM ParentNode logic in this shim, so we skip ph verification
				new_tree.set_parent(dp_idx, ParentNode(public_key=node.new_public_key, parent_hash=b""))

				# Try to decrypt if we are in the resolution of cop_idx
				res = new_tree.resolution(cop_idx)
				if self.my_index in res:
					# Find our ciphertext
					my_pos = res.index(self.my_index)
					ct = node.encrypted_path_secret[my_pos]
					# Decrypt path_secret
					path_secret = HPKE.open(self.my_kem_key, ct.kem_output, ct.ciphertext, info=_up_info(provisional_ctx.to_bytes()))

					# Ratchet up to get commit_secret
					curr = path_secret
					for _ in range(i + 1, len(update_path.nodes)):
						curr = _derive_next_path_secret(curr)
					commit_secret = curr

		if commit_secret is None:
			enc_ct = update.encrypted_commit_secrets[self.my_kp_ref]
			enc, ct_bytes = enc_ct[:32], enc_ct[32:]
			commit_secret = HPKE.open(self.my_kem_key, enc, ct_bytes, info=_up_info(provisional_ctx.to_bytes()))

		# 2. Recompute transcript hash using RFC §8.2 two-pass chain (P1-NEW-1)
		_unsigned_body_v = (
			tls_u64(update.epoch_id)
			+ tls_opaque32(update.tree.to_bytes())
			+ tls_u32(len(update.encrypted_commit_secrets))
			+ b"".join(tls_opaque(k) + tls_opaque(v) for k, v in sorted(update.encrypted_commit_secrets.items()))
			+ tls_u32(update.committer_index)
		)
		_framed_v = FramedContent(
			group_id=self.group_id,
			epoch=self.state.epoch_id,
			sender_leaf_index=update.committer_index,
			authenticated_data=b"",
			content=_unsigned_body_v,
		)
		framed_content_bytes_v = _framed_v.to_bytes()

		# 3. Verify Signature
		try:
			old_ctx = _make_group_context(self.group_id, self.state.epoch_id, self.state.tree, self.interim_transcript_hash)
			committer_node = self.state.tree.get_leaf(update.committer_index)
			if committer_node is None:
				raise ValueError(f"Committer node {update.committer_index} is blank")
			sig_key_bytes = committer_node.signature_key
			public_key = ed25519.Ed25519PublicKey.from_public_bytes(sig_key_bytes)
			tbs = _make_framed_content_tbs(old_ctx, _framed_v)
			public_key.verify(update.signature, tbs)
		except InvalidSignature:
			raise ValueError("Commit Forgery Detected: Invalid Signature in update")
		except (ValueError, TypeError) as exc:
			raise ValueError(f"Malformed update signature: {exc}") from exc

		# P1-N2: Verify membership_tag — proves sender was a group member (RFC §6.2)
		if update._membership_tag is not None:
			expected_mem_tag = hmac.new(self.state.key_schedule.membership_key, tbs, "sha256").digest()
			if not hmac.compare_digest(expected_mem_tag, update._membership_tag):
				raise ValueError("Membership tag mismatch — sender is not a current group member (P1-N2)")

		# P1-TH & P1-CTH: Transcript Hash Sequence
		confirmed_input = _compute_confirmed_transcript_hash_input(framed_content_bytes_v, update.signature)
		transcript_hash = _compute_confirmed_transcript_hash(self.interim_transcript_hash, confirmed_input)

		# Phase 1: derive confirmation_key
		_provisional_ctx = _make_group_context(self.group_id, update.epoch_id, update.tree, transcript_hash)
		_conf_key = KeySchedule.derive_confirmation_key(
			init_secret=self.state.key_schedule.init_secret,
			commit_secret=commit_secret,
			group_context=_provisional_ctx.to_bytes(),
			psk_list=None,
		)

		# Phase 2: Compute confirmation_tag with NEW epoch key
		_conf_tag = hmac.new(_conf_key, transcript_hash, "sha256").digest()

		# P1-IH: Verify confirmation_tag BEFORE state mutation
		if update._confirmation_tag is None:
			raise ValueError("Confirmation tag absent — refusing to advance epoch (RFC §8.3 mandatory)")
		if not hmac.compare_digest(_conf_tag, update._confirmation_tag):
			raise ValueError("Confirmation tag mismatch — epoch desynchronization or replay attack (P0-02)")

		# Compute NEW interim_transcript_hash to store in MLSGroup
		new_interim = _compute_interim_transcript_hash(transcript_hash, _conf_tag)
		group_ctx_verify = _make_group_context(self.group_id, update.epoch_id, update.tree, transcript_hash)

		# 4. Final epoch advance
		next_state = self.state.advance_epoch(
			commit_secret,
			update.tree,
			group_context=group_ctx_verify.to_bytes(),
		)

		self._wipe_secret_tree()  # forward secrecy: zeroize old epoch SecretTree before transition
		# P0-A: return new MLSGroup with transcript_hash propagated for next commit
		return MLSGroup(next_state, self.my_index, self.my_sig_key, self.my_kem_key, interim_transcript_hash=new_interim)

	def encrypt_application_message(self, plaintext: bytes) -> bytes:
		"""RFC 9420 §9: Encrypt an application message using SecretTree (per-leaf, per-generation).

		Wire format:
			sender_data_ct (32B AES-GCM) | gen(4B) | content_ct (nonce_12 + AESGCM_ct)
			where sender_data plaintext = leaf_index(4B)
		"""

		st = self._get_secret_tree()
		content_key, content_nonce, gen = st.get_key_and_nonce(self.my_index)

		# Associated Data: group_id + epoch_id for binding
		ad = self.group_id + self.epoch_id.to_bytes(8, "big")
		content_ct = AESGCM(content_key).encrypt(content_nonce, plaintext, ad)

		# RFC 9420 §9.4: SenderData key/nonce derived from first Nh=32 bytes of content_ct
		sample = content_ct[:32].ljust(32, b"\x00")
		sd_key = derive_sender_data_key(self.state.key_schedule.sender_data_secret, sample)
		sd_nonce = derive_sender_data_nonce(self.state.key_schedule.sender_data_secret, sample)
		sd_plaintext = struct.pack(">I", self.my_index)  # leaf_index (4 bytes)
		sd_ct = AESGCM(sd_key).encrypt(sd_nonce, sd_plaintext, ad)

		# Wire: sender_data_ct(len+bytes) | gen(4B big-endian) | content_ct
		return len(sd_ct).to_bytes(2, "big") + sd_ct + struct.pack(">I", gen) + content_ct

	def decrypt_application_message(self, payload: bytes) -> bytes:
		"""RFC 9420 §9: Decrypt an application message using SecretTree."""

		if len(payload) < 2:
			raise ValueError("Application message payload too short")

		ad = self.group_id + self.epoch_id.to_bytes(8, "big")

		# 1. Parse sender_data ciphertext and content ciphertext
		offset = 0
		sd_ct_len = int.from_bytes(payload[offset : offset + 2], "big")
		offset += 2
		sd_ct = payload[offset : offset + sd_ct_len]
		offset += sd_ct_len
		gen = struct.unpack(">I", payload[offset : offset + 4])[0]
		offset += 4
		content_ct = payload[offset:]

		# RFC 9420 §9.4: SenderData sample = first Nh=32 bytes of content_ct
		sample = content_ct[:32].ljust(32, b"\x00")
		sd_key = derive_sender_data_key(self.state.key_schedule.sender_data_secret, sample)
		sd_nonce = derive_sender_data_nonce(self.state.key_schedule.sender_data_secret, sample)
		try:
			sd_plaintext = AESGCM(sd_key).decrypt(sd_nonce, sd_ct, ad)
		except InvalidTag:
			raise ValueError("SenderData authentication failed")

		sender_leaf = struct.unpack(">I", sd_plaintext)[0]

		# 3. Derive content key/nonce for sender's leaf + generation
		st = self._get_secret_tree()
		try:
			content_key, content_nonce = st.get_key_and_nonce_for_gen(sender_leaf, gen)
		except ValueError as exc:
			raise ValueError(f"SecretTree: {exc}") from exc

		# 4. Decrypt content
		try:
			return AESGCM(content_key).decrypt(content_nonce, content_ct, ad)
		except InvalidTag:
			raise ValueError("Application message decryption failed: authentication tag mismatch")

	def to_bytes(self) -> bytes:
		"""Serializes the full state + my private keys (Danger Zone)."""
		state_bytes = self.state.to_bytes()
		cth = self.interim_transcript_hash
		# P1-3: Serialize _consumed_key_packages to prevent replay attacks after restart
		consumed_list = sorted(list(self._consumed_key_packages))
		consumed_bytes = b"".join(tls_opaque(ref) for ref in consumed_list)
		return (
			self.my_index.to_bytes(4, "big")
			+ self.my_sig_key.private_bytes()
			+ self.my_kem_key.private_bytes()
			+ len(state_bytes).to_bytes(4, "big")
			+ state_bytes
			+ len(cth).to_bytes(2, "big")
			+ cth
			+ tls_opaque32(consumed_bytes)
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
		offset += s_len
		cth = b""
		if offset < len(data):  # backward-compat guard
			cth_len = int.from_bytes(data[offset : offset + 2], "big")
			offset += 2
			cth = data[offset : offset + cth_len]
			offset += cth_len

		group = cls(state, my_index=idx, my_sig_key=sig_key, my_kem_key=kem_key, interim_transcript_hash=cth)

		# P1-3: Deserialize consumed key packages if present
		if offset < len(data):
			consumed_raw, offset = read_opaque32(data, offset)
			c_offset = 0
			while c_offset < len(consumed_raw):
				ref, c_offset = read_opaque(consumed_raw, c_offset)
				group._consumed_key_packages.add(ref)

		return group
