"""ECDHE P-256 key exchange using cryptography library."""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_ecdhe_keypair() -> tuple:
    """
    Generate an ECDHE P-256 keypair.
    
    Returns:
        (private_key_obj, public_key_bytes) where public_key_bytes is in DER format
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, bytes(public_key_bytes)


def ecdhe_compute_shared(private_key_obj, peer_public_key_bytes: bytes) -> bytes:
    """
    Compute shared secret using ECDH.
    
    Args:
        private_key_obj: our private key object
        peer_public_key_bytes: peer's public key in DER format
        
    Returns:
        shared_secret as bytes
    """
    peer_public_key = serialization.load_der_public_key(peer_public_key_bytes)
    shared_secret = private_key_obj.exchange(ec.ECDH(), peer_public_key)
    return bytes(shared_secret)
