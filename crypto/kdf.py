"""HKDF key derivation function."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_session_key(kyber_secret: bytes, ecdhe_secret: bytes) -> bytes:
    """
    Derive a 256-bit session key from Kyber and ECDHE shared secrets.
    
    Args:
        kyber_secret: shared secret from Kyber KEM
        ecdhe_secret: shared secret from ECDHE
        
    Returns:
        32-byte session key suitable for AES-256
    """
    ikm = kyber_secret + ecdhe_secret
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'PQ-Messenger-Salt-v1',
        info=b'session-key'
    )
    
    session_key = hkdf.derive(ikm)
    return bytes(session_key)
