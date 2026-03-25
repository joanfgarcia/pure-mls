import hashlib
import pytest
from pure_mls.keyschedule import KeySchedule

def test_key_schedule_epoch_0_suite_1():
    """
    Official RFC 9420 Test Vector for Key Schedule (Suite 1).
    Source: https://github.com/mlswg/mls-implementations/blob/main/test-vectors/key-schedule.json
    """
    initial_init_secret = bytes.fromhex("a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e")
    commit_secret = bytes.fromhex("a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509")
    group_context = bytes.fromhex("0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00")

    # Expected results for Epoch 0 Suite 1
    expected_joiner_secret = bytes.fromhex("4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d")
    expected_encryption_secret = bytes.fromhex("01588615c93d02c83bda0b587473303b1637a92bf80783206d963f9197c40a13")
    expected_exporter_secret = bytes.fromhex("5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea")
    expected_auth_secret = bytes.fromhex("7375d449cde2c5a856c13c8eb52c16bf9ef29eceef59b09d1f946bd1bac24643")
    expected_confirmation_key = bytes.fromhex("feabd690de3b4ce985a3dfad86a4c4e6a0be9b84e7cc764842784f2a6b938b75")
    expected_membership_key = bytes.fromhex("970744ba7edd21700a3e106cb4e2b4c657cef6b41a1fe5b5a1418f86e76e037e")
    expected_sender_data_secret = bytes.fromhex("9b3995e08589548b75e149190060cf35228df0eefe3527ea2fb39e49a84125b4")
    expected_init_secret = bytes.fromhex("505be2ce2ff922aa11e0a03d76346dda2981f1d9edf5cf98ecfc8757f69b00c9")
    psk_secret = bytes.fromhex("e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b")

    # Derivation
    ks = KeySchedule.derive(initial_init_secret, commit_secret, group_context, psk_secret)
    
    print(f"Derived Joiner: {ks.joiner_secret.hex()}")
    print(f"Derived Epoch:  {ks.epoch_secret.hex()}")
    assert ks.joiner_secret == expected_joiner_secret, f"joiner_secret mismatch: {ks.joiner_secret.hex()}"
    assert ks.encryption_secret == expected_encryption_secret, f"encryption_secret mismatch: {ks.encryption_secret.hex()}"
    assert ks.exporter_secret == expected_exporter_secret, f"exporter_secret mismatch: {ks.exporter_secret.hex()}"
    assert ks.authentication_secret == expected_auth_secret, f"authentication_secret mismatch: {ks.authentication_secret.hex()}"
    assert ks.confirmation_key == expected_confirmation_key, f"confirmation_key mismatch: {ks.confirmation_key.hex()}"
    assert ks.sender_data_secret == expected_sender_data_secret, f"sender_data_secret mismatch: {ks.sender_data_secret.hex()}"
    assert ks.next_init_secret == expected_init_secret, f"next_init_secret mismatch: {ks.next_init_secret.hex()}"
    
    # Membership key check
    m_key = KeySchedule.derive_membership_key(ks.epoch_secret)
    assert m_key == expected_membership_key, f"membership_key mismatch: {m_key.hex()}"

if __name__ == "__main__":
    test_key_schedule_epoch_0_suite_1()
    print("ALL TESTS PASSED")
