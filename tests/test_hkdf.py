import os
import hashlib
from pure_mls.hkdf import hkdf_extract, hkdf_expand
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def test_hkdf_parity_with_openssl():
    """
    Assert that our zero-dependency pure Python HKDF implementation
    produces the exact same output keying material (OKM) as the deeply 
    tested C-compiled OpenSSL primitives from cryptography.io.
    """
    salt = os.urandom(32)
    ikm = os.urandom(32)
    info = b"mls_test_context"
    length = 64
    
    # Pure Python
    prk = hkdf_extract(salt, ikm, hashlib.sha256)
    okm_pure = hkdf_expand(prk, info, length, hashlib.sha256)
    
    # OpenSSL (cryptography)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    okm_crypto = hkdf.derive(ikm)
    
    assert okm_pure == okm_crypto, "Parity check failed against OpenSSL HKDF"

def test_hkdf_no_salt():
    ikm = os.urandom(48)
    info = b"mls_empty_salt"
    length = 42
    
    # RFC 5869 specifies empty salt defaults to a string of HashLen zeros
    prk = hkdf_extract(b"", ikm, hashlib.sha384)
    okm_pure = hkdf_expand(prk, info, length, hashlib.sha384)
    
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=length,
        salt=None,
        info=info,
    )
    okm_crypto = hkdf.derive(ikm)
    
    assert okm_pure == okm_crypto
