"""AES-256-GCM authenticated encryption."""

import os
from Crypto.Cipher import AES


def aes_gcm_encrypt(key: bytes, plaintext: str) -> dict:
    """
    Encrypt plaintext using AES-256-GCM.
    
    Args:
        key: 32-byte AES key
        plaintext: message string to encrypt
        
    Returns:
        dict with 'nonce', 'ciphertext', 'tag' as hex strings
    """
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    
    return {
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex()
    }


def aes_gcm_decrypt(key: bytes, payload: dict) -> str:
    """
    Decrypt AES-GCM ciphertext and verify tag.
    
    Args:
        key: 32-byte AES key
        payload: dict with 'nonce', 'ciphertext', 'tag' as hex strings
        
    Returns:
        decrypted plaintext string
        
    Raises:
        ValueError: if authentication tag is invalid
    """
    nonce = bytes.fromhex(payload['nonce'])
    ciphertext = bytes.fromhex(payload['ciphertext'])
    tag = bytes.fromhex(payload['tag'])
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext.decode()


# ── Bytes-native overloads (used by ratchet and test suite) ───────────────────

def encrypt_bytes(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt bytes using AES-256-GCM.

    Args:
        key:       32-byte AES-256 key
        plaintext: arbitrary bytes to encrypt

    Returns:
        (nonce, ciphertext, tag) — all bytes objects
        nonce = 12 bytes, tag = 16 bytes
    """
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext and verify authentication tag.

    Args:
        key:        32-byte AES-256 key
        nonce:      12-byte nonce used during encryption
        ciphertext: encrypted bytes
        tag:        16-byte authentication tag

    Returns:
        decrypted plaintext bytes

    Raises:
        ValueError: if authentication tag verification fails (ciphertext tampered)
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
