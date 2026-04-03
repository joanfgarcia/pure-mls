import copy
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

	def __post_init__(self) -> None:
		# Prevent mutation of the RatchetTree through the immutable EpochState

		cloned = copy.deepcopy(self.tree)
		cloned.freeze()  # STATE-03: enforce immutability after deepcopy
		super().__setattr__("tree", cloned)

	def advance_epoch(
		self,
		commit_secret: bytes,
		next_tree: RatchetTree,
		transcript_hash: bytes = b"",
		group_context: bytes = b"",
		psk_list: list[tuple[bytes, bytes]] | None = None,
	) -> "EpochState":
		"""Transitions the group to the next cryptographic era."""
		next_schedule = KeySchedule.derive(
			init_secret=self.key_schedule.init_secret,
			commit_secret=commit_secret,
			group_context=group_context,
			psk_list=psk_list,
		)
		return EpochState(group_id=self.group_id, epoch_id=self.epoch_id + 1, tree=next_tree, key_schedule=next_schedule)

	@classmethod
	def genesis(
		cls,
		group_id: bytes,
		creator_tree: RatchetTree,
		group_context_bytes: bytes = b"",
	) -> "EpochState":
		"""Bootstraps Epoch 0 for a brand new sovereign group.

		RFC 9420 §8.1: epoch 0 init_secret is the all-zeros vector.

		group_context_bytes MUST be the TLS-serialised GroupContext for epoch 0
		(group_id, epoch=0, tree_hash, confirmed_transcript_hash=b\"\").
		Passing b\"\" (default) skips domain separation — use only in tests that
		explicitly target the genesis-only code path without a full group context.

		The caller (group.py) constructs the GroupContext and passes it here to
		avoid a circular import: epoch.py → group.py → epoch.py.
		"""
		genesis_init = b"\x00" * 32  # RFC 9420 §8.1: epoch 0 init_secret = zeros
		blank_commit = b"\x00" * 32

		return cls(
			group_id=group_id,
			epoch_id=0,
			tree=creator_tree,
			key_schedule=KeySchedule.derive(genesis_init, blank_commit, group_context=group_context_bytes),
		)

	def to_bytes(self) -> bytes:
		"""Full EpochState binary dump for persistence."""
		tree_bytes = self.tree.to_bytes()
		return (
			len(self.group_id).to_bytes(2, "big")
			+ self.group_id
			+ self.epoch_id.to_bytes(8, "big")
			+ len(tree_bytes).to_bytes(4, "big")
			+ tree_bytes
			+ self.key_schedule.to_bytes()
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "EpochState":
		offset = 0
		gid_len = int.from_bytes(data[offset : offset + 2], "big")
		offset += 2
		gid = data[offset : offset + gid_len]
		offset += gid_len
		eid = int.from_bytes(data[offset : offset + 8], "big")
		offset += 8
		t_len = int.from_bytes(data[offset : offset + 4], "big")
		offset += 4
		tree = RatchetTree.from_bytes(data[offset : offset + t_len])
		offset += t_len
		ks = KeySchedule.from_bytes(data[offset : offset + KeySchedule.SIZE])
		return cls(group_id=gid, epoch_id=eid, tree=tree, key_schedule=ks)
