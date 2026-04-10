"""RFC 9420 §13.4 Extensions Framework.

Extensions are used to provide additional information in various MLS structures:
- KeyPackage (§7)
- LeafNode (§7.2)
- GroupContext (§12.1)
- Welcome (§12.4.3)
"""

from dataclasses import dataclass, field
from typing import List

from pure_mls.tls import (
	ExtensionType,
	read_extensions,
	read_opaque,
	read_u8,
	tls_extensions,
	tls_opaque,
	tls_u8,
	tls_u16,
	tls_varint,
)


@dataclass
class Capabilities:
	"""RFC 9420 §7.2: Capabilities of a client or group.

	Fields are vectors (<V>) with VarInt length prefixes, as per OpenMLS interop.
	"""

	versions: List[int] = field(default_factory=lambda: [1])  # MLS 1.0 (u16 elements)
	ciphersuites: List[int] = field(default_factory=lambda: [0x0001])
	extensions: List[int] = field(default_factory=lambda: [1, 2, 4])  # Cap, Tree, ExtPSK
	proposals: List[int] = field(default_factory=lambda: [1, 2, 3])  # Add, Update, Remove
	credentials: List[int] = field(default_factory=lambda: [1])  # Basic

	@classmethod
	def default(cls) -> "Capabilities":
		"""Returns default capabilities for MLS 1.0."""
		return cls()

	def marshal(self) -> bytes:
		"""Standard MLS serialization using VarInt prefixes."""
		res = b""

		def tls_vec_varint(vals: List[int]) -> bytes:
			body = b"".join(tls_u16(v) for v in vals)
			return tls_varint(len(body)) + body

		res += tls_vec_varint(self.versions)
		res += tls_vec_varint(self.ciphersuites)
		res += tls_vec_varint(self.extensions)
		res += tls_vec_varint(self.proposals)
		res += tls_vec_varint(self.credentials)
		return res

	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int = 0) -> tuple["Capabilities", int]:
		"""Context-aware parsing matching OpenMLS wire format."""

		# RFC 9420 §7.2: Capabilities vectors have range <0..255>, meaning 1st byte is length (uint8).
		# OpenMLS and standard MLS implementations follow this TLS 1.3 convention.
		def read_u8_vec(buf: bytes, off: int) -> tuple[List[int], int]:
			length, off = read_u8(buf, off)
			raw = buf[off : off + length]
			# Elements are uint16 as per RFC 9420 Appendix B
			values = [int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2)]
			return values, off + length

		versions, offset = read_u8_vec(data, offset)
		ciphersuites, offset = read_u8_vec(data, offset)
		extensions, offset = read_u8_vec(data, offset)
		proposals, offset = read_u8_vec(data, offset)
		credentials, offset = read_u8_vec(data, offset)
		return cls(versions, ciphersuites, extensions, proposals, credentials), offset

	@classmethod
	def unmarshal(cls, data: bytes) -> "Capabilities":
		obj, _ = cls.from_bytes_at(data, 0)
		return obj


@dataclass
class RatchetTreeExtension:
	"""RFC 9420 §12.4.3.3: Provides the full ratchet tree state."""

	tree_data: bytes  # vec<optional<Node>> in serialized form

	def marshal(self) -> bytes:
		return self.tree_data

	@classmethod
	def unmarshal(cls, data: bytes) -> "RatchetTreeExtension":
		return cls(tree_data=data)


@dataclass
class ExternalPSKExtension:
	"""RFC 9420 §12.4.3.4: Preshared Key ID for external PSK usage."""

	psk_id: bytes
	psk_nonce: bytes

	def marshal(self) -> bytes:
		# PreSharedKeyID psk_id;
		# struct { psk_type=external, psk_id<V>, psk_nonce<V> }
		res = tls_u8(1)  # external=1
		res += tls_opaque(self.psk_id)
		res += tls_opaque(self.psk_nonce)
		return res

	@classmethod
	def unmarshal(cls, data: bytes) -> "ExternalPSKExtension":
		offset = 0
		psk_type, offset = read_u8(data, offset)
		if psk_type != 1:
			raise ValueError(f"Unsupported PSK type: {psk_type}")
		psk_id, offset = read_opaque(data, offset)
		psk_nonce, offset = read_opaque(data, offset)
		return cls(psk_id, psk_nonce)


@dataclass
class GroupContextExtensions:
	"""RFC 9420 §12.1.7: Extensions applied to the GroupContext."""

	extensions: List[tuple[ExtensionType, bytes]] = field(default_factory=list)

	def marshal(self) -> bytes:
		# RFC 9420 §12.1.1: Extension extensions<V>;
		return tls_extensions(self.extensions)

	@classmethod
	def unmarshal(cls, data: bytes) -> "GroupContextExtensions":
		exts, _ = read_extensions(data, 0)
		return cls(exts)
