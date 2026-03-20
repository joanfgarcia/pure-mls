import os
from dataclasses import dataclass

from pure_mls.keyschedule import KeySchedule
from pure_mls.tree import RatchetTree


@dataclass(frozen=True)
class EpochState:
	"""
	The absolute definition of the Group State at any point in time.
	If two disconnected nodes have mathematically identical EpochStates,
	they are cryptographically synchronized.
	"""

	group_id: bytes
	epoch_id: int
	tree: RatchetTree
	key_schedule: KeySchedule

	def advance_epoch(self, commit_secret: bytes, next_tree: RatchetTree, transcript_hash: bytes = b"epoch") -> "EpochState":
		"""
		Transitions the group to the next cryptographic Era.
		Consumes the next_init_secret from the current era and mixes it with the
		new commit_secret derived from the TreeKEM operations.
		"""
		next_schedule = KeySchedule.derive(
			init_secret=self.key_schedule.next_init_secret, commit_secret=commit_secret, transcript_hash=transcript_hash
		)
		return EpochState(group_id=self.group_id, epoch_id=self.epoch_id + 1, tree=next_tree, key_schedule=next_schedule)

	@classmethod
	def genesis(cls, group_id: bytes, creator_tree: RatchetTree) -> "EpochState":
		"""Bootstraps Epoch 0 for a brand new sovereign group."""
		genesis_init = os.urandom(32)
		blank_commit = b"\x00" * 32

		return cls(group_id=group_id, epoch_id=0, tree=creator_tree, key_schedule=KeySchedule.derive(genesis_init, blank_commit))
