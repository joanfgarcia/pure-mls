"""TLS presentation language primitives for RFC 9420 wire format.

RFC 9420 uses the TLS 1.3 presentation language (RFC 8446 §3) for all structures.
This module provides the minimal encoding / decoding primitives needed.

Encoding conventions:
	- all integers: big-endian
	- opaque<V>: uint16 length prefix + bytes  (variable-length vector)
	- opaque[N]: N bytes fixed			   (used internally, no prefix)
	- vec<T>: uint32 length prefix + concatenated serialized elements
"""

import struct
from enum import IntEnum
from typing import Any, List, Protocol

# Fixed-width integers


def tls_u8(v: int) -> bytes:
	return struct.pack(">B", v)


def tls_u16(v: int) -> bytes:
	return struct.pack(">H", v)


def tls_u32(v: int) -> bytes:
	return struct.pack(">I", v)


def tls_u64(v: int) -> bytes:
	return struct.pack(">Q", v)


# Variable-length octet strings (opaque<V>)
# RFC 9420 uses MLS VarInt length prefix (shortest possible representation).


def tls_opaque(data: bytes) -> bytes:
	"""Encode bytes as opaque<V> with MLS VarInt length prefix (RFC 9420 §3.2)."""
	return tls_varint(len(data)) + data


# Alias for backward compatibility with tests
tls_opaque_varint = tls_opaque


def tls_opaque16(data: bytes) -> bytes:
	"""Encode bytes with uint16 length prefix (non-standard / legacy)."""
	return tls_u16(len(data)) + data


def tls_opaque32(data: bytes) -> bytes:
	"""Encode bytes with uint32 length prefix."""
	return tls_u32(len(data)) + data


def tls_vec8(data: bytes) -> bytes:
	"""Encode bytes with uint8 length prefix."""
	if len(data) > 0xFF:
		raise ValueError(f"vec8 overflow: {len(data)} > 255")
	return struct.pack(">B", len(data)) + data


# Decoding: Reader helpers
# All return (value, new_offset)


def read_u8(buf: bytes, offset: int) -> tuple[int, int]:
	return buf[offset], offset + 1


def read_u16(buf: bytes, offset: int) -> tuple[int, int]:
	(v,) = struct.unpack_from(">H", buf, offset)
	return v, offset + 2


def read_u32(buf: bytes, offset: int) -> tuple[int, int]:
	(v,) = struct.unpack_from(">I", buf, offset)
	return v, offset + 4


def read_u64(buf: bytes, offset: int) -> tuple[int, int]:
	(v,) = struct.unpack_from(">Q", buf, offset)
	return v, offset + 8


def read_opaque(buf: bytes, offset: int) -> tuple[bytes, int]:
	"""Decode opaque<V> with MLS VarInt length prefix (RFC 9420 §3.2)."""
	length, offset = _varint_decode(buf, offset)
	if offset + length > len(buf):
		raise ValueError(f"MLS TLS Parsing: opaque length {length} exceeds buffer size (offset {offset}, buffer {len(buf)})")
	return buf[offset : offset + length], offset + length


def read_opaque16(buf: bytes, offset: int) -> tuple[bytes, int]:
	"""Decode opaque<V> with uint16 length prefix (non-standard / legacy)."""
	(length,) = struct.unpack_from(">H", buf, offset)
	offset += 2
	return buf[offset : offset + length], offset + length


def read_opaque32(buf: bytes, offset: int) -> tuple[bytes, int]:
	"""Decode opaque<V> with uint32 length prefix."""
	(length,) = struct.unpack_from(">I", buf, offset)
	offset += 4
	return buf[offset : offset + length], offset + length


def read_fixed(buf: bytes, offset: int, n: int) -> tuple[bytes, int]:
	"""Read exactly n bytes (opaque[N])."""
	return buf[offset : offset + n], offset + n


# MLS VarInt encoding (RFC 9420 §5.1 / §C)
# Used for variable-length vector fields in Welcome/KDF TLS wire format.


def _varint_decode(buf: bytes, offset: int) -> tuple[int, int]:
	"""Decode an MLS variable-length integer (VarInt) from buf at offset.

	Returns (value, new_offset).
	Encoding:
	0x00-0x3F: 1 byte  (top 2 bits = 00)
	0x40-0x7F: 2 bytes (top 2 bits = 01)
	0x80-0xBF: 4 bytes (top 2 bits = 10)
	"""
	first = buf[offset]
	prefix = (first >> 6) & 0x3
	if prefix == 0:
		return first & 0x3F, offset + 1
	elif prefix == 1:
		return ((first & 0x3F) << 8) | buf[offset + 1], offset + 2
	elif prefix == 2:
		v = ((first & 0x3F) << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]
		return v, offset + 4
	raise ValueError("Invalid varint prefix 0b11")


def tls_varint(n: int) -> bytes:
	"""Encode n as an MLS VarInt."""
	if n <= 0x3F:
		return bytes([n])
	elif n <= 0x3FFF:
		return ((n | 0x4000) & 0xFFFF).to_bytes(2, "big")
	elif n <= 0x3FFFFFFF:
		return ((n | 0x80000000) & 0xFFFFFFFF).to_bytes(4, "big")
	raise ValueError(f"VarInt out of range: {n}")


def read_vector16(buf: bytes, offset: int) -> tuple[bytes, int]:
	"""Read a vector with a 2-byte length prefix (uint16)."""
	(length,) = struct.unpack_from(">H", buf, offset)
	offset += 2
	return buf[offset : offset + length], offset + length


def read_vector32(buf: bytes, offset: int) -> tuple[bytes, int]:
	"""Read a vector with a 4-byte length prefix (uint32)."""
	(length,) = struct.unpack_from(">I", buf, offset)
	offset += 4
	return buf[offset : offset + length], offset + length


def read_extensions16(buf: bytes, offset: int) -> tuple[List[tuple[int, bytes]], int]:
	"""Read an Extension vector with a 2-byte length prefix."""
	data, offset = read_vector16(buf, offset)
	return _parse_extensions_internal(data), offset


def read_extensions32(buf: bytes, offset: int) -> tuple[List[tuple[int, bytes]], int]:
	"""Read an Extension vector with a 4-byte length prefix."""
	data, offset = read_vector32(buf, offset)
	return _parse_extensions_internal(data), offset


def _parse_extensions_internal(data: bytes) -> List[tuple[int, bytes]]:
	"""Internal helper to parse a sequence of raw extension blocks."""
	exts = []
	i = 0
	while i < len(data):
		etype = int.from_bytes(data[i : i + 2], "big")
		elen = int.from_bytes(data[i + 2 : i + 4], "big")
		edata = data[i + 4 : i + 4 + elen]
		exts.append((etype, edata))
		i += 4 + elen
	return exts


def read_vec8(buf: bytes, offset: int) -> tuple[bytes, int]:
	"""Decode vec<T> with uint8 length prefix."""
	length = buf[offset]
	offset += 1
	return buf[offset : offset + length], offset + length


# MLS Extensions (RFC 9420 §13.4)


class ExtensionType(IntEnum):
	CAPABILITIES = 0x0001
	RATCHET_TREE = 0x0002
	EXTERNAL_PUB = 0x0003
	EXTERNAL_PSK = 0x0004
	RESUMPTION_PSK = 0x0005
	APP_ACK = 0x0006


def tls_extension(ext_type: int, data: bytes) -> bytes:
	"""Native MLS: Encode an Extension: uint16 type + VarInt-prefixed data (RFC 9420 §13.2)."""
	return tls_u16(ext_type) + tls_opaque(data)


def tls_extension16(ext_type: int, data: bytes) -> bytes:
	"""TLS-Style: Encode an Extension: uint16 type + uint16-prefixed data (Appendix B)."""
	return tls_u16(ext_type) + tls_opaque16(data)


def read_extension(buf: bytes, offset: int) -> tuple[tuple[int, bytes], int]:
	"""Native MLS: Decode an Extension: (type, data), new_offset. Uses VarInt."""
	ext_type, offset = read_u16(buf, offset)
	ext_data, offset = read_opaque(buf, offset)
	return (ext_type, ext_data), offset


def read_extension16(buf: bytes, offset: int) -> tuple[tuple[int, bytes], int]:
	"""TLS-Style: Decode an Extension: (type, data), new_offset. Uses uint16."""
	ext_type, offset = read_u16(buf, offset)
	ext_data, offset = read_opaque16(buf, offset)
	return (ext_type, ext_data), offset


def tls_extensions(extensions: list[tuple[int, bytes]]) -> bytes:
	"""Native MLS: Encode a vec<Extension> with VarInt length prefix."""
	body = b"".join(tls_extension(t, d) for t, d in extensions)
	return tls_varint(len(body)) + body


def tls_extensions16(extensions: list[tuple[int, bytes]]) -> bytes:
	"""TLS-Style: Encode a vec<Extension> with uint16 length prefix (Appendix B)."""
	body = b"".join(tls_extension16(t, d) for t, d in extensions)
	return tls_u16(len(body)) + body


def read_extensions(buf: bytes, offset: int) -> tuple[list[tuple[int, bytes]], int]:
	"""Native MLS: Decode a vec<Extension> with VarInt length prefix."""
	raw_exts, offset = read_opaque(buf, offset)
	sub_offset = 0
	res = []
	while sub_offset < len(raw_exts):
		ext, sub_offset = read_extension(raw_exts, sub_offset)
		res.append(ext)
	return res, offset


class Parsable(Protocol):
	@classmethod
	def from_bytes_at(cls, data: bytes, offset: int) -> tuple[Any, int]: ...


def read_vector(buf: bytes, offset: int, cls: type[Parsable]) -> tuple[list[Any], int]:
	"""Decode vec<T> with MLS VarInt length prefix."""
	# vec<T> is basically opaque<V> interpreted as elements
	opaque_bytes, offset = read_opaque(buf, offset)
	sub_offset = 0
	res = []
	while sub_offset < len(opaque_bytes):
		val, sub_offset = cls.from_bytes_at(opaque_bytes, sub_offset)
		res.append(val)
	return res, offset
