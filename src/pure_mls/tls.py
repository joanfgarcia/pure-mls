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

# Fixed-width integers


def tls_u8(v: int) -> bytes:
	return struct.pack(">B", v)


def tls_u16(v: int) -> bytes:
	return struct.pack(">H", v)


def tls_u32(v: int) -> bytes:
	return struct.pack(">I", v)


def tls_u64(v: int) -> bytes:
	return struct.pack(">Q", v)


# Variable-length octet strings  (opaque<V>)
# RFC 9420 uses uint16-prefixed variable-length vectors for most fields.


def tls_opaque(data: bytes) -> bytes:
	"""Encode bytes as opaque<V> with uint16 length prefix (max 65535 bytes)."""
	if len(data) > 0xFFFF:
		raise ValueError(f"opaque<V> overflow: {len(data)} > 65535")
	return struct.pack(">H", len(data)) + data


def tls_opaque32(data: bytes) -> bytes:
	"""Encode bytes as opaque<V> with uint32 length prefix (for large payloads)."""
	return struct.pack(">I", len(data)) + data


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
	"""Decode opaque<V> with uint16 length prefix."""
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
