"""
RFC 9420 (MLS) Interoperability Test Suite — IETF Official Test Vectors.

Source:
    https://github.com/mlswg/mls-implementations/blob/main/test-vectors/key-schedule.json
    Repository: https://github.com/mlswg/mls-implementations (IETF MLS Working Group)
    Commit pinned: main branch (fetched at test time, with embedded fallback)

Verification:
    Any auditor can reproduce these vectors by:
    1. Cloning https://github.com/mlswg/mls-implementations
    2. Reading test-vectors/key-schedule.json
    3. Comparing the cipher_suite=1 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) epochs
       against the assertions below.

Test strategy:
    - Fetches the live JSON when network is available (marks test SKIP if unreachable,
      NOT fail — CI without network should not break).
    - Falls back to an embedded snapshot of the first 2 epochs of Suite 1
      so the test always has a baseline without network.
    - Validates: joiner_secret, epoch_authenticator, encryption_secret,
      exporter_secret, confirmation_key, sender_data_secret, membership_key,
      next init_secret for every epoch in the chain.
"""

import json
import urllib.request
from urllib.error import URLError

import pytest

from pure_mls.keyschedule import KeySchedule

# ---------------------------------------------------------------------------
# Source of truth
# ---------------------------------------------------------------------------
_VECTOR_URL = "https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/key-schedule.json"
_CIPHER_SUITE = 1  # MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

# ---------------------------------------------------------------------------
# Embedded fallback snapshot — Suite 1, epochs 0 and 1.
# Extracted directly from mlswg/mls-implementations @ main (2026-03-25).
# Enables offline / network-free CI to still run a baseline assertion.
# ---------------------------------------------------------------------------
_FALLBACK_EPOCHS = [
	{
		"commit_secret": "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509",
		"psk_secret": "e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b",
		"group_context": (
			"0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"
			"0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818"
			"205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00"
		),
		"joiner_secret": "4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d",
		"epoch_authenticator": "7375d449cde2c5a856c13c8eb52c16bf9ef29eceef59b09d1f946bd1bac24643",
		"encryption_secret": "01588615c93d02c83bda0b587473303b1637a92bf80783206d963f9197c40a13",
		"exporter_secret": "5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea",
		"confirmation_key": "feabd690de3b4ce985a3dfad86a4c4e6a0be9b84e7cc764842784f2a6b938b75",
		"sender_data_secret": "9b3995e08589548b75e149190060cf35228df0eefe3527ea2fb39e49a84125b4",
		"membership_key": "970744ba7edd21700a3e106cb4e2b4c657cef6b41a1fe5b5a1418f86e76e037e",
		"init_secret": "505be2ce2ff922aa11e0a03d76346dda2981f1d9edf5cf98ecfc8757f69b00c9",
	},
	{
		"commit_secret": "7b3027aa5d2224aab7e2a18660bbf57930e2e21d95e02b849c704d970e3e28c5",
		"psk_secret": "ca7a68f2a8a52147d70f1eb7195de968d2e182b93596bc5a61393861e91180e4",
		"group_context": (
			"0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"
			"000000000000000120826a4d3b0956277ce5e272e4d18fdca023ffb63ea4cea636e34cc837ae7c5c5"
			"d2014a2985ea47db0685924a74d47ac8a08ec241f843b536dd1348e3ffb2d78184e00"
		),
		"joiner_secret": "7ba2c5eed466d6fa8de0b0f33553c7b336a2580c03820e79f22e9416efc5b9f9",
		"epoch_authenticator": "4bdbe62402b3caaadaf5c6fafd89db4db5ac7c7532f3e47d35c82b3998570361",
		"encryption_secret": "c607312fab6423cd728a25fd91e9905e058518d1bf171984ed5f4e4e057fa3be",
		"exporter_secret": "047d983048b132b79ea4e2e578afd02a0f4717d166cefe46e43e2e965b5c9f4e",
		"confirmation_key": "04ab9a788afe377d34b0fac1dc26085c85ac55a63e44b88da39fb4e58a898979",
		"sender_data_secret": "64035464638ac7cf16583644e8117a84ca3c101eaa34a86ad4ead9524f8fb9bc",
		"membership_key": "1eb0202e445ebc744c00eb42951ad67638c51cc9a468d9035be06612ff5cd89a",
		"init_secret": "88586b2252f06838106a97f5ad1f3357d99d718be8f44f61ab103be653fc608a",
	},
]

_INITIAL_INIT_SECRET = "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fetch_live_epochs() -> list[dict] | None:
	"""Fetch Suite 1 epochs from the IETF repository. Returns None on network error."""
	try:
		with urllib.request.urlopen(_VECTOR_URL, timeout=8) as resp:
			data = json.loads(resp.read())
		for suite in data:
			if suite["cipher_suite"] == _CIPHER_SUITE:
				return suite["epochs"]
	except (URLError, json.JSONDecodeError, KeyError):
		pass
	return None


def _run_epoch_chain(epochs: list[dict], init_secret_hex: str) -> None:
	"""Drives the key schedule through an epoch chain and asserts all derived secrets."""
	init_secret = bytes.fromhex(init_secret_hex)

	for i, epoch in enumerate(epochs):
		commit_secret = bytes.fromhex(epoch["commit_secret"])
		group_context = bytes.fromhex(epoch["group_context"])
		psk_secret = bytes.fromhex(epoch["psk_secret"])

		ks = KeySchedule.derive(init_secret, commit_secret, group_context, psk_secret)

		# --- assert all epoch secrets ---
		assert ks.joiner_secret == bytes.fromhex(epoch["joiner_secret"]), f"Epoch {i}: joiner_secret mismatch"
		assert ks.epoch_authenticator == bytes.fromhex(epoch["epoch_authenticator"]), f"Epoch {i}: epoch_authenticator mismatch"
		assert ks.encryption_secret == bytes.fromhex(epoch["encryption_secret"]), f"Epoch {i}: encryption_secret mismatch"
		assert ks.exporter_secret == bytes.fromhex(epoch["exporter_secret"]), f"Epoch {i}: exporter_secret mismatch"
		assert ks.confirmation_key == bytes.fromhex(epoch["confirmation_key"]), f"Epoch {i}: confirmation_key mismatch"
		assert ks.sender_data_secret == bytes.fromhex(epoch["sender_data_secret"]), f"Epoch {i}: sender_data_secret mismatch"
		assert KeySchedule.derive_membership_key(ks.epoch_secret) == bytes.fromhex(epoch["membership_key"]), f"Epoch {i}: membership_key mismatch"
		assert ks.next_init_secret == bytes.fromhex(epoch["init_secret"]), f"Epoch {i}: next init_secret mismatch"

		# Chain: next epoch starts from the init_secret derived in this one
		init_secret = ks.next_init_secret


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_ietf_key_schedule_fallback_suite1():
	"""
	Baseline interop test against embedded IETF vectors (no network required).

	Source: mlswg/mls-implementations, test-vectors/key-schedule.json
	Suite:  cipher_suite=1 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
	Epochs: 0–1 (embedded snapshot, auditor-reproducible from the URL above)
	"""
	_run_epoch_chain(_FALLBACK_EPOCHS, _INITIAL_INIT_SECRET)


@pytest.mark.network
def test_ietf_key_schedule_live_suite1():
	"""
	Full interop test fetching vectors live from the IETF repository.

	Skipped automatically when network is unavailable.
	Source: https://github.com/mlswg/mls-implementations/blob/main/test-vectors/key-schedule.json
	"""
	epochs = _fetch_live_epochs()
	if epochs is None:
		pytest.skip("IETF vector endpoint unreachable — skipping live interop test")
	_run_epoch_chain(epochs, _INITIAL_INIT_SECRET)
