"""Audit M2: add_member tree hygiene — reuse blank leaves (no unbounded growth) and keep
multi-member commits decryptable regardless of committer position."""

from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


def _kp(sig: SignatureKey, kem: KemKey) -> KeyPackage:
	return KeyPackage.create(
		encryption_key=kem.public_bytes(),
		init_key_pub=kem.public_bytes(),
		signature_key=sig.public_bytes(),
		identity=sig.public_bytes(),
		sign_fn=sig.sign,
	)


def _ident() -> tuple[SignatureKey, KemKey]:
	return SignatureKey(), KemKey()


def _build(n: int) -> dict[int, MLSGroup]:
	ids = [_ident() for _ in range(n)]
	group = MLSGroup.create(b"g", ids[0][0], ids[0][1])
	members = {0: group}
	for i in range(1, n):
		sig, kem = ids[i]
		group, welcome, update = group.add_member(_kp(sig, kem))
		for j in range(1, i):
			members[j] = members[j].process_update(update)
		members[i] = MLSGroup.join(welcome, sig, kem)
		members[0] = group
	return members


def _all_decrypt(members: dict[int, MLSGroup], committer: int) -> bool:
	rotated, commit = members[committer].update_key()
	advanced = {committer: rotated}
	for j, member in members.items():
		if j != committer:
			advanced[j] = member.process_update(commit)
	msg = advanced[committer].encrypt_application_message(b"payload")
	return all(g.decrypt_application_message(msg) == b"payload" for g in advanced.values())


def test_far_leaf_committer_all_decrypt() -> None:
	for n in (2, 3, 4, 5, 6):
		members = _build(n)
		assert _all_decrypt(members, committer=n - 1), f"n={n}: not all members decrypted"


def test_add_reuses_blank_leaf_after_removal() -> None:
	members = _build(4)  # leaves 0..3
	creator = members[0]
	# remove leaf 2 (node index 4); remaining members process it
	creator, remove_commit = creator.remove_member(4)
	members[1] = members[1].process_update(remove_commit)
	members[3] = members[3].process_update(remove_commit)

	before = creator.state.tree.num_leaves
	sig, kem = _ident()
	creator, welcome, add_commit = creator.add_member(_kp(sig, kem))
	# the freed slot must be reused, not appended -> tree does not grow
	assert creator.state.tree.num_leaves == before, "blank leaf was not reused"

	members[1] = members[1].process_update(add_commit)
	members[3] = members[3].process_update(add_commit)
	members[0] = creator
	members[2] = MLSGroup.join(welcome, sig, kem)

	# a commit by the member on the reused leaf must decrypt for everyone
	assert _all_decrypt(members, committer=2)
