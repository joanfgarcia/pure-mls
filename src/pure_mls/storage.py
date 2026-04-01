import asyncio
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pure_mls.group import MLSGroup


class AsyncEncryptedStore:
	"""
	Secure persistence layer for MLS Groups using AES-256-GCM.
	Each group state is stored in a separate file, encrypted with a vault key.
	"""

	def __init__(self, storage_dir: str, vault_key: bytes):
		"""
		Initialize the store.
		vault_key MUST be 32 bytes (AES-256).
		"""
		self.storage_dir = storage_dir
		self.vault_key = vault_key
		if len(vault_key) != 32:
			raise ValueError("Vault key must be 32 bytes (AES-256)")

		# Ensure storage directory exists
		os.makedirs(storage_dir, exist_ok=True)

	def _get_path(self, group_id: bytes) -> str:
		# Use hex of group_id for filename
		filename = f"group_{group_id.hex()}.mls"
		return os.path.join(self.storage_dir, filename)

	async def save_group(self, group: MLSGroup) -> None:
		"""
		Encrypt and save an MLSGroup state to disk.
		Uses AES-GCM with a random 12-byte nonce.
		"""
		data = group.to_bytes()
		nonce = os.urandom(12)
		aesgcm = AESGCM(self.vault_key)

		# Encrypt (ciphertext includes the 16-byte authentication tag)
		ciphertext = aesgcm.encrypt(nonce, data, group.group_id)

		# Final payload: [nonce (12)] + [ciphertext (tag+data)]
		payload = nonce + ciphertext

		path = self._get_path(group.group_id)

		def _write() -> None:
			with open(path, "wb") as f:
				f.write(payload)

		await asyncio.to_thread(_write)

	async def load_group(self, group_id: bytes) -> MLSGroup | None:
		"""
		Load and decrypt an MLSGroup state from disk.
		Returns None if the file does not exist.
		"""
		path = self._get_path(group_id)
		if not os.path.exists(path):
			return None

		def _read() -> bytes:
			with open(path, "rb") as f:
				return f.read()

		payload = await asyncio.to_thread(_read)

		if len(payload) < 28:
			raise ValueError("Stored payload is too short")

		nonce = payload[:12]
		ciphertext = payload[12:]

		aesgcm = AESGCM(self.vault_key)
		try:
			# Decrypt (passing group_id as associated data for integrity check)
			data = aesgcm.decrypt(nonce, ciphertext, group_id)
			return MLSGroup.from_bytes(data)
		except (InvalidTag, ValueError) as e:
			raise ValueError(f"Failed to decrypt or parse group state: {e}")

	async def delete_group(self, group_id: bytes) -> bool:
		"""Removes the group state from disk."""
		path = self._get_path(group_id)
		if os.path.exists(path):
			await asyncio.to_thread(os.remove, path)
			return True
		return False
