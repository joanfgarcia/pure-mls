import os

import pytest

from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.storage import AsyncEncryptedStore


@pytest.mark.asyncio
async def test_encrypted_storage_roundtrip(tmp_path):
	# 1. Setup
	storage_dir = str(tmp_path / "mls_storage")
	vault_key = b"A" * 32  # 256-bit key
	store = AsyncEncryptedStore(storage_dir, vault_key)

	group_id = b"test-group-001"
	sig_key = SignatureKey()
	kem_key = KemKey()

	# 2. Create Group
	group = MLSGroup.create(group_id, sig_key, kem_key)

	# 3. Save
	await store.save_group(group)

	# Verify file exists
	expected_path = os.path.join(storage_dir, f"group_{group_id.hex()}.mls")
	assert os.path.exists(expected_path)

	# 4. Load
	loaded_group = await store.load_group(group_id)

	# 5. Verify State
	assert loaded_group is not None
	assert loaded_group.group_id == group.group_id
	assert loaded_group.epoch_id == group.epoch_id
	assert loaded_group.my_index == group.my_index
	assert loaded_group.state.key_schedule.encryption_secret == group.state.key_schedule.encryption_secret

	# Verify keys (private)
	assert loaded_group.my_sig_key.private_bytes() == sig_key.private_bytes()
	assert loaded_group.my_kem_key.private_bytes() == kem_key.private_bytes()


@pytest.mark.asyncio
async def test_invalid_vault_key(tmp_path):
	storage_dir = str(tmp_path / "mls_storage")
	vault_key_a = b"A" * 32
	vault_key_b = b"B" * 32

	store_a = AsyncEncryptedStore(storage_dir, vault_key_a)
	store_b = AsyncEncryptedStore(storage_dir, vault_key_b)

	group_id = b"secure-group"
	group = MLSGroup.create(group_id, SignatureKey(), KemKey())

	await store_a.save_group(group)

	# Attempt to load with wrong key should fail
	with pytest.raises(ValueError, match="Failed to decrypt"):
		await store_b.load_group(group_id)


@pytest.mark.asyncio
async def test_delete_group(tmp_path):
	storage_dir = str(tmp_path / "mls_storage")
	store = AsyncEncryptedStore(storage_dir, b"K" * 32)
	group_id = b"to-be-deleted"
	group = MLSGroup.create(group_id, SignatureKey(), KemKey())

	await store.save_group(group)
	assert await store.delete_group(group_id) is True
	assert await store.load_group(group_id) is None
	assert await store.delete_group(group_id) is False
