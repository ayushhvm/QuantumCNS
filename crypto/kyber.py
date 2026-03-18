"""CRYSTALS-Kyber KEM wrapper using liboqs."""

import ctypes as ct

import oqs


def generate_kyber_keypair() -> tuple[bytes, bytes]:
    """
    Generate a Kyber512 keypair.
    
    Returns:
        (public_key, private_key) as bytes
    """
    kem = oqs.KeyEncapsulation('Kyber512')
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return bytes(public_key), bytes(secret_key)


def kyber_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret to a public key.
    
    Args:
        public_key: recipient's public key bytes
        
    Returns:
        (ciphertext, shared_secret) as bytes
    """
    kem = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return bytes(ciphertext), bytes(shared_secret)


def kyber_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate a ciphertext using a private key.
    
    Args:
        private_key: recipient's private key bytes
        ciphertext: encapsulated ciphertext bytes
        
    Returns:
        shared_secret as bytes
    """
    kem = oqs.KeyEncapsulation('Kyber512')
    kem.secret_key = ct.create_string_buffer(private_key, kem._kem.contents.length_secret_key)
    shared_secret = kem.decap_secret(ciphertext)
    return bytes(shared_secret)
