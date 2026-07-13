"""Codec plugin system for handling wire-format variations in MLS dialects.

Implements the SerializerStrategy protocol and auto-detect logic for different dialects.
"""

import struct
from typing import Dict, List, Protocol, Tuple

from pure_mls.tls import (
	_varint_decode,
	read_opaque,
	read_u16,
	tls_opaque,
	tls_u16,
	tls_u32,
	tls_varint,
)


class SerializerStrategy(Protocol):
	"""Strategy interface for handling wire-format variations in MLS dialects."""

	@property
	def name(self) -> str:
		"""Return the dialect name identifier."""
		...

	def header(self) -> bytes:
		"""Return the prefix or header prepended to messages in this dialect."""
		...

	def welcome_label(self) -> bytes:
		"""Return the label used for Welcome HPKE info context derivation."""
		...

	def encode_extensions(self, extensions: List[Tuple[int, bytes]]) -> bytes:
		"""Encode a list of extensions according to dialect-specific rules."""
		...

	def decode_extensions(self, buf: bytes, offset: int) -> Tuple[List[Tuple[int, bytes]], int]:
		"""Decode a list of extensions according to dialect-specific rules."""
		...

	def encode_vector(self, items: List[bytes]) -> bytes:
		"""Encode a list of serialized items prefixed by their length."""
		...

	def decode_vector(self, buf: bytes, offset: int) -> Tuple[List[bytes], int]:
		"""Decode a list of serialized items prefixed by their length."""
		...

	def detect(self, data: bytes) -> bool:
		"""Check if the raw data matches this dialect's fingerprint."""
		...


class StandardStrategy:
	"""Standard RFC 9420 Serializer Strategy (also used by OpenMLS)."""

	@property
	def name(self) -> str:
		return "standard"

	def header(self) -> bytes:
		return b""

	def welcome_label(self) -> bytes:
		return b"MLS 1.0 Welcome"

	def encode_extensions(self, extensions: List[Tuple[int, bytes]]) -> bytes:
		body = b"".join(tls_u16(t) + tls_opaque(d) for t, d in extensions)
		return tls_varint(len(body)) + body

	def decode_extensions(self, buf: bytes, offset: int) -> Tuple[List[Tuple[int, bytes]], int]:
		raw_exts, offset = read_opaque(buf, offset)
		sub_offset = 0
		res = []
		while sub_offset < len(raw_exts):
			ext_type, sub_offset = read_u16(raw_exts, sub_offset)
			ext_data, sub_offset = read_opaque(raw_exts, sub_offset)
			res.append((ext_type, ext_data))
		return res, offset

	def encode_vector(self, items: List[bytes]) -> bytes:
		body = b"".join(items)
		return tls_varint(len(body)) + body

	def decode_vector(self, buf: bytes, offset: int) -> Tuple[List[bytes], int]:
		length, offset = _varint_decode(buf, offset)
		if offset + length > len(buf):
			raise ValueError("Vector length exceeds buffer size")
		end = offset + length
		res = []
		# In MLS, vector elements themselves are parsed by callers,
		# here we chunk them if they are length-prefixed, or return the raw block.
		# For decoding, we return the sub-buffer to let the caller decode individual elements.
		res.append(buf[offset:end])
		return res, end

	def detect(self, data: bytes) -> bool:
		# Standard MLSMessage(Welcome) starts with MLS version (00 01) and wire_format Welcome (00 03)
		return data.startswith(b"\x00\x01\x00\x03")


class CiscoStrategy:
	"""Cisco MLS dialect using TLS-style (Appendix B) fixed 16-bit length prefixes."""

	@property
	def name(self) -> str:
		return "cisco"

	def header(self) -> bytes:
		return b"\xcc\x01"

	def welcome_label(self) -> bytes:
		# Cisco uses a dialect-specific welcome label
		return b"Cisco MLS Welcome"

	def encode_extensions(self, extensions: List[Tuple[int, bytes]]) -> bytes:
		# uint16 prefix for extensions and each extension data
		body = b"".join(tls_u16(t) + tls_u16(len(d)) + d for t, d in extensions)
		return tls_u16(len(body)) + body

	def decode_extensions(self, buf: bytes, offset: int) -> Tuple[List[Tuple[int, bytes]], int]:
		(length,) = struct.unpack_from(">H", buf, offset)
		offset += 2
		end = offset + length
		res = []
		while offset < end:
			ext_type, offset = read_u16(buf, offset)
			(elen,) = struct.unpack_from(">H", buf, offset)
			offset += 2
			ext_data = buf[offset : offset + elen]
			offset += elen
			res.append((ext_type, ext_data))
		return res, offset

	def encode_vector(self, items: List[bytes]) -> bytes:
		body = b"".join(items)
		return tls_u16(len(body)) + body

	def decode_vector(self, buf: bytes, offset: int) -> Tuple[List[bytes], int]:
		(length,) = struct.unpack_from(">H", buf, offset)
		offset += 2
		end = offset + length
		return [buf[offset:end]], end

	def detect(self, data: bytes) -> bool:
		# Cisco dialect might start with a custom dialect header, e.g., 0xCC 0x01
		return data.startswith(b"\xcc\x01")


class MlsppStrategy:
	"""mlspp dialect with custom welcome label and uint32 vector length prefixes."""

	@property
	def name(self) -> str:
		return "mlspp"

	def header(self) -> bytes:
		return b"\xaa\x02"

	def welcome_label(self) -> bytes:
		return b"mlspp Welcome"

	def encode_extensions(self, extensions: List[Tuple[int, bytes]]) -> bytes:
		# Standard extensions encoding
		body = b"".join(tls_u16(t) + tls_opaque(d) for t, d in extensions)
		return tls_varint(len(body)) + body

	def decode_extensions(self, buf: bytes, offset: int) -> Tuple[List[Tuple[int, bytes]], int]:
		raw_exts, offset = read_opaque(buf, offset)
		sub_offset = 0
		res = []
		while sub_offset < len(raw_exts):
			ext_type, sub_offset = read_u16(raw_exts, sub_offset)
			ext_data, sub_offset = read_opaque(raw_exts, sub_offset)
			res.append((ext_type, ext_data))
		return res, offset

	def encode_vector(self, items: List[bytes]) -> bytes:
		body = b"".join(items)
		return tls_u32(len(body)) + body

	def decode_vector(self, buf: bytes, offset: int) -> Tuple[List[bytes], int]:
		(length,) = struct.unpack_from(">I", buf, offset)
		offset += 4
		end = offset + length
		return [buf[offset:end]], end

	def detect(self, data: bytes) -> bool:
		# mlspp dialect might start with a custom dialect header, e.g., 0xAA 0x02
		return data.startswith(b"\xaa\x02")


# Global Registry
_REGISTRY: Dict[str, SerializerStrategy] = {
	"standard": StandardStrategy(),
	"cisco": CiscoStrategy(),
	"mlspp": MlsppStrategy(),
}


def register_dialect(strategy: SerializerStrategy) -> None:
	"""Register a new custom codec strategy."""
	_REGISTRY[strategy.name] = strategy


def get_dialect(name: str) -> SerializerStrategy:
	"""Retrieve a registered dialect strategy by name."""
	if name not in _REGISTRY:
		raise KeyError(f"Dialect '{name}' is not registered.")
	return _REGISTRY[name]


def detect_dialect(data: bytes) -> SerializerStrategy:
	"""Auto-detect the dialect of the raw message based on fingerprints."""
	for strategy in _REGISTRY.values():
		if strategy.detect(data):
			return strategy
	# Default to standard if none detected
	return _REGISTRY["standard"]
