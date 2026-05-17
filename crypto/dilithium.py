"""
ML-DSA-65 Digital Signature wrapper.

Algorithm: ML-DSA-65 (formerly Dilithium3, NIST FIPS 204)
Library:   liboqs-python 0.14.1 / liboqs native 0.15.0
Security:  NIST Level 3 — 128-bit post-quantum security

IMPORTANT: "Dilithium3" is NOT available in liboqs 0.15.0.
           ML-DSA-65 is the STANDARDIZED NIST FIPS 204 name for the same algorithm.
           All code and UI should display "ML-DSA-65 (Dilithium3)" for clarity.

Verified key/signature sizes:
  public key:  1952 bytes
  secret key:  4032 bytes
  signature:   3309 bytes (max; may be shorter due to variable-length encoding)
"""

import oqs

# Exact algorithm name as returned by oqs.get_enabled_sig_mechanisms()
# "Dilithium3" NOT present in liboqs 0.15.0 — ML-DSA-65 is correct.
DILITHIUM_ALG = "ML-DSA-65"


class DilithiumSigner:
    """
    ML-DSA-65 (Dilithium3) signature scheme.

    Three operations:
      - generate_keypair: produce a long-term identity keypair
      - sign:   produce a signature over a message using secret key
      - verify: verify a signature using public key — NEVER raises on bad sig

    NOTE: sign() requires a fresh oqs.Signature object initialized with secret_key.
          Verified: secret_key kwarg works in liboqs-python 0.14.1 / native 0.15.0.
    """

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """
        Generate an ML-DSA-65 identity keypair.

        Returns:
            (public_key, secret_key) as bytes
            public_key:  1952 bytes
            secret_key:  4032 bytes
        """
        with oqs.Signature(DILITHIUM_ALG) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        return bytes(public_key), bytes(secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """
        Sign a message with the given secret key.

        Args:
            secret_key: ML-DSA-65 secret key (4032 bytes)
            message:    arbitrary bytes to sign

        Returns:
            signature bytes (≤ 3309 bytes)

        Raises:
            RuntimeError: if liboqs signing fails (malformed key)
        """
        with oqs.Signature(DILITHIUM_ALG, secret_key=secret_key) as signer:
            signature = signer.sign(message)
        return bytes(signature)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature. Returns False on any failure — never raises.

        This is intentional: callers should treat invalid signatures as
        a potential MITM and surface this clearly in the UI.

        Args:
            public_key: ML-DSA-65 public key (1952 bytes)
            message:    the signed message
            signature:  the signature to verify

        Returns:
            True if valid, False otherwise
        """
        try:
            with oqs.Signature(DILITHIUM_ALG) as verifier:
                return bool(verifier.verify(message, signature, public_key))
        except Exception:
            # Any exception (wrong key size, corrupt sig, etc.) → treat as invalid
            return False
