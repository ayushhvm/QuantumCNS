"""
Kyber768 Key Encapsulation Mechanism (KEM) wrapper.

Algorithm: Kyber768 (equivalent to ML-KEM-768, NIST FIPS 203)
Library:   liboqs-python 0.14.1 / liboqs native 0.15.0
Security:  NIST Level 3 — 128-bit post-quantum security

Verified key/ciphertext sizes:
  public key:  1184 bytes
  secret key:  2400 bytes
  ciphertext:  1088 bytes
  shared secret: 32 bytes
"""

import oqs

# Exact algorithm name as returned by oqs.get_enabled_kem_mechanisms()
# Verified present in liboqs 0.15.0. "Dilithium3" is NOT available — use ML-DSA-65.
KYBER_ALG = "Kyber768"


class KyberKEM:
    """
    Kyber768 KEM.

    Usage pattern — always use context managers inside liboqs:
        encapsulate: create fresh KEM, call encap_secret()
        decapsulate: create fresh KEM with secret_key kwarg, call decap_secret()

    NOTE: liboqs requires fresh KEM objects per operation. Do NOT reuse instances.
    """

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """
        Generate a Kyber768 keypair.

        Returns:
            (public_key, secret_key) as bytes
            public_key:  1184 bytes
            secret_key:  2400 bytes
        """
        with oqs.KeyEncapsulation(KYBER_ALG) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return bytes(public_key), bytes(secret_key)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate a shared secret to the given public key.

        Args:
            public_key: recipient's Kyber768 public key (1184 bytes)

        Returns:
            (ciphertext, shared_secret) as bytes
            ciphertext:    1088 bytes
            shared_secret:   32 bytes
        """
        with oqs.KeyEncapsulation(KYBER_ALG) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate a ciphertext using the secret key.

        Args:
            secret_key: Kyber768 secret key (2400 bytes)
            ciphertext: encapsulated ciphertext (1088 bytes)

        Returns:
            shared_secret (32 bytes) — must equal the encapsulator's shared_secret

        Raises:
            RuntimeError: if liboqs decapsulation fails (malformed ciphertext)
        """
        # Verified: secret_key kwarg works in liboqs-python 0.14.1 with native 0.15.0
        with oqs.KeyEncapsulation(KYBER_ALG, secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return bytes(shared_secret)
