import argparse

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


def main():
	parser = argparse.ArgumentParser(description="Pure-MLS Command Line Interface", prog="pure-mls")
	subparsers = parser.add_subparsers(dest="command", help="commands")
	subparsers.required = True

	# keygen
	p_keygen = subparsers.add_parser("keygen", help="Generate a new identity and KeyPackage")
	p_keygen.add_argument("alias", help="Alias for the user (will create <alias>.pub and <alias>.priv)")

	# create-group
	p_create = subparsers.add_parser("create-group", help="Create a brand new MLS group")
	p_create.add_argument("group_id", help="Name/ID of the group")
	p_create.add_argument("founder_priv", help="Path to founder's .priv file")
	p_create.add_argument("--out", "-o", required=True, help="Path to save the group state (.state)")

	# add-member
	p_add = subparsers.add_parser("add-member", help="Add a new member to an existing group")
	p_add.add_argument("group_state", help="Path to the group state (.state)")
	p_add.add_argument("invitee_pub", help="Path to the invitee's public KeyPackage (.pub)")
	p_add.add_argument("--out-welcome", "-w", required=True, help="Path to save the Welcome message")
	p_add.add_argument("--out-state", "-o", help="Overwrites group state by default, unless specified here")

	# join-group
	p_join = subparsers.add_parser("join-group", help="Join a group from a Welcome message")
	p_join.add_argument("welcome", help="Path to the Welcome message")
	p_join.add_argument("my_priv", help="Path to your private keys (.priv)")
	p_join.add_argument("--out-state", "-o", required=True, help="Path to save your group state (.state)")

	args = parser.parse_args()

	if args.command == "keygen":
		sig_key = SignatureKey(private_key=ed25519.Ed25519PrivateKey.generate())
		kem_key = KemKey(private_key=x25519.X25519PrivateKey.generate())
		kp = KeyPackage.create(
			encryption_key=kem_key.public_bytes(),
			init_key_pub=kem_key.public_bytes(),
			signature_key=sig_key.public_bytes(),
			identity=args.alias.encode(),
			sign_fn=sig_key.sign,
		)

		# Simplistic serialization: 32 bytes sig priv + 32 bytes kem priv + (pubkeys inside KeyPackage)
		priv_data = sig_key.private_bytes() + kem_key.private_bytes()
		with open(f"{args.alias}.priv", "wb") as f:
			f.write(priv_data)
		with open(f"{args.alias}.pub", "wb") as f:
			f.write(kp.to_bytes())
		print(f"Created {args.alias}.priv (KEEP SECRET!) and {args.alias}.pub (Distribute freely)")

	elif args.command == "create-group":
		with open(args.founder_priv, "rb") as f:
			pd = f.read()
		sig_key = SignatureKey.from_private_bytes(pd[:32])
		kem_key = KemKey.from_private_bytes(pd[32:64])

		group = MLSGroup.create(args.group_id.encode(), sig_key, kem_key)
		with open(args.out, "wb") as f:
			f.write(group.to_bytes())
		print(f"Created group '{args.group_id}' (state saved to {args.out})")

	elif args.command == "add-member":
		with open(args.group_state, "rb") as f:
			group = MLSGroup.from_bytes(f.read())
		with open(args.invitee_pub, "rb") as f:
			kp, _ = KeyPackage.from_bytes_at(f.read())

		new_group, welcome, commit = group.add_member(kp)

		out_state = args.out_state if args.out_state else args.group_state
		with open(out_state, "wb") as f:
			f.write(new_group.to_bytes())
		with open(args.out_welcome, "wb") as f:
			f.write(welcome.to_bytes())
		print(f"Added member! State updated at {out_state}. Distribute {args.out_welcome} to the new member.")

	elif args.command == "join-group":
		with open(args.my_priv, "rb") as f:
			pd = f.read()
		sig_key = SignatureKey.from_private_bytes(pd[:32])
		kem_key = KemKey.from_private_bytes(pd[32:64])

		with open(args.welcome, "rb") as f:
			welcome_data = f.read()

		group = MLSGroup.join(welcome_data, sig_key, kem_key)
		with open(args.out_state, "wb") as f:
			f.write(group.to_bytes())
		gid = group.state.group_id.decode(errors="replace")
		print(f"Successfully joined group '{gid}'! State saved to {args.out_state}")


if __name__ == "__main__":
	main()
