import oqs
from config import get_logger, SIG_ALG
from config import MLDSA65_PUBKEY_LEN, MLDSA65_SECKEY_LEN

logger = get_logger(__name__)


class DilithiumSigner:
    """
    Wrapper around ML-DSA-65 (FIPS 204).
    All methods operate on raw bytes.
    """

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """
        Generate a fresh ML-DSA-65 keypair.
        Returns (public_key, secret_key) as bytes.
        """
        with oqs.Signature(SIG_ALG) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()

        if len(public_key) != MLDSA65_PUBKEY_LEN:
            raise RuntimeError(
                f"ML-DSA-65 pubkey size mismatch: "
                f"expected {MLDSA65_PUBKEY_LEN}, got {len(public_key)}"
            )
        if len(secret_key) != MLDSA65_SECKEY_LEN:
            raise RuntimeError(
                f"ML-DSA-65 seckey size mismatch: "
                f"expected {MLDSA65_SECKEY_LEN}, got {len(secret_key)}"
            )

        logger.debug(
            "ML-DSA-65 keypair generated — pubkey_len=%d, seckey_len=%d",
            len(public_key), len(secret_key)
        )
        return public_key, secret_key

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """
        Sign a message with the given secret key.
        Returns signature as bytes.
        """
        if len(secret_key) != MLDSA65_SECKEY_LEN:
            raise ValueError(
                f"ML-DSA-65 sign: invalid seckey length "
                f"{len(secret_key)}, expected {MLDSA65_SECKEY_LEN}"
            )

        try:
            with oqs.Signature(SIG_ALG, secret_key=secret_key) as signer:
                signature = signer.sign(message)
        except Exception as exc:
            logger.error("ML-DSA-65 signing failed: %s", exc)
            raise RuntimeError(f"ML-DSA-65 signing failed: {exc}") from exc

        logger.debug("ML-DSA-65 signature produced — sig_len=%d", len(signature))
        return signature

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature.
        Returns True if valid, False if invalid.
        Never raises on invalid signature — only raises on unexpected errors.
        """
        if len(public_key) != MLDSA65_PUBKEY_LEN:
            raise ValueError(
                f"ML-DSA-65 verify: invalid pubkey length "
                f"{len(public_key)}, expected {MLDSA65_PUBKEY_LEN}"
            )

        try:
            with oqs.Signature(SIG_ALG) as verifier:
                result = verifier.verify(message, signature, public_key)
        except Exception as exc:
            logger.error("ML-DSA-65 verify raised exception: %s", exc)
            return False

        if not result:
            logger.warning("ML-DSA-65 signature verification returned False")
        else:
            logger.debug("ML-DSA-65 signature verified: True")

        return result
