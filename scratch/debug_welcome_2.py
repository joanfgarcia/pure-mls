
import json
import hashlib
import hmac
from pure_mls.hkdf import hkdf_extract, expand_with_label, derive_secret
from pure_mls.keyschedule import _psk_secret, PreSharedKeyID, PSK_TYPE_EXTERNAL

def _h(s): return bytes.fromhex(s)

def run_diag():
    with open("tests/ietf_vectors/passive-client-welcome.json") as f:
        data = json.load(f)
    
    # Vector 2 (PSK case)
    vec = data[2]
    print(f"DIAGNOSTIC FOR VECTOR 2")
    
    # We simulate decyption of joiner_secret
    # In welcome-2, joiner_secret is 32 bytes.
    # We dont have GS in JSON directly, but we have it from our previous run (we saw it decrypted).
    # Since we passed GroupInfo decryption, we know our psk_secret and welcome_key are correct.
    
    # LETS TEST THE PSK SECRET CHAIN
    psk_list = []
    for psk_data in vec.get("external_psks", []):
        psk_id = _h(psk_data["psk_id"])
        psk_val = _h(psk_data["psk"])
        psk_list.append((PreSharedKeyID(psk_type=PSK_TYPE_EXTERNAL, psk_id=psk_id, psk_nonce=b""), psk_val))
    
    psk_secret = _psk_secret(psk_list)
    print(f"psk_secret: {psk_secret.hex()}")

    # To get joiner_secret, I'll run the test briefly and print it.
    # OR better: I'll trust that the decryption worked.
    # Since I'm in the Bünker, I'll just run a snippet that joins and prints.
    
if __name__ == "__main__":
    run_diag()
