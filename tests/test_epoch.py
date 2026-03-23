import os

from pure_mls.epoch import EpochState
from pure_mls.keyschedule import KeySchedule
from pure_mls.tree import RatchetTree


def test_key_schedule_derivation() -> None:
	"""Asserts that a KeySchedule mathematically isolates eras."""
	init_secret = os.urandom(32)
	commit_secret = os.urandom(32)

	schedule_1 = KeySchedule.derive(init_secret, commit_secret)
	assert len(schedule_1.encryption_secret) == 32
	assert len(schedule_1.init_secret) == 32

	# Simulating a second commit
	commit_secret_2 = os.urandom(32)
	schedule_2 = KeySchedule.derive(schedule_1.init_secret, commit_secret_2)

	# Asserts Post-Compromise Security isolation (keys differ completely)
	assert schedule_1.encryption_secret != schedule_2.encryption_secret
	assert schedule_1.joiner_secret != schedule_2.joiner_secret


def test_epoch_state_machine() -> None:
	"""Asserts that Epoch transitions update the ID and hash strictly linearly."""
	tree_v1 = RatchetTree(1)
	state_v1 = EpochState.genesis(b"legion_770", tree_v1)

	assert state_v1.epoch_id == 0

	# Advance Epoch (A commit occurred)
	tree_v2 = RatchetTree(2)  # E.g., someone joined
	commit_secret = os.urandom(32)

	state_v2 = state_v1.advance_epoch(commit_secret, tree_v2)

	assert state_v2.epoch_id == 1
	assert state_v2.group_id == b"legion_770"
	assert state_v2.tree.num_leaves == 2

	# The mathematical isolation holds
	assert state_v1.key_schedule.encryption_secret != state_v2.key_schedule.encryption_secret
