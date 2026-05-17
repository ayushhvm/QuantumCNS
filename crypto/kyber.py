import oqs
from config import get_logger, KEM_ALG
from config import MLKEM768_PUBKEY_LEN, MLKEM768_SECKEY_LEN
from config import MLKEM768_CIPHERTEXT_LEN, MLKEM768_SS_LEN

logger = get_logger(__name__)


class KyberKEM:
    """
    Wrapper around ML-KEM-768 (FIPS 203).
    All methods return raw bytes. No hex encoding at this layer.
    """

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """
        Generate a fresh ML-KEM-768 keypair.
        Returns (public_key, secret_key) as bytes.
        Raises RuntimeError if key sizes are unexpected.
        """
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()

        if len(public_key) != MLKEM768_PUBKEY_LEN:
            raise RuntimeError(
                f"ML-KEM-768 pubkey size mismatch: "
                f"expected {MLKEM768_PUBKEY_LEN}, got {len(public_key)}"
            )
        if len(secret_key) != MLKEM768_SECKEY_LEN:
            raise RuntimeError(
                f"ML-KEM-768 seckey size mismatch: "
                f"expected {MLKEM768_SECKEY_LEN}, got {len(secret_key)}"
            )

        logger.debug(
            "ML-KEM-768 keypair generated — "
            "pubkey_len=%d, seckey_len=%d", len(public_key), len(secret_key)
        )
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the recipient's public key.
        Returns (ciphertext, shared_secret) as bytes.
        Raises ValueError if public_key length is wrong.
        Raises RuntimeError if output sizes are unexpected.
        """
        if len(public_key) != MLKEM768_PUBKEY_LEN:
            raise ValueError(
                f"ML-KEM-768 encapsulate: invalid pubkey length "
                f"{len(public_key)}, expected {MLKEM768_PUBKEY_LEN}"
            )

        try:
            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
        except Exception as exc:
            logger.error("ML-KEM-768 encapsulation failed: %s", exc)
            raise RuntimeError(f"ML-KEM-768 encapsulation failed: {exc}") from exc

        if len(ciphertext) != MLKEM768_CIPHERTEXT_LEN:
            raise RuntimeError(
                f"ML-KEM-768 ciphertext size mismatch: "
                f"expected {MLKEM768_CIPHERTEXT_LEN}, got {len(ciphertext)}"
            )
        if len(shared_secret) != MLKEM768_SS_LEN:
            raise RuntimeError(
                f"ML-KEM-768 shared secret size mismatch: "
                f"expected {MLKEM768_SS_LEN}, got {len(shared_secret)}"
            )

        logger.debug(
            "ML-KEM-768 encapsulation complete — "
            "ciphertext_len=%d, ss_len=%d", len(ciphertext), len(shared_secret)
        )
        return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate to recover the shared secret.
        Returns shared_secret as bytes.
        Raises ValueError if input lengths are wrong.
        Raises RuntimeError if output size is unexpected.
        """
        if len(secret_key) != MLKEM768_SECKEY_LEN:
            raise ValueError(
                f"ML-KEM-768 decapsulate: invalid seckey length "
                f"{len(secret_key)}, expected {MLKEM768_SECKEY_LEN}"
            )
        if len(ciphertext) != MLKEM768_CIPHERTEXT_LEN:
            raise ValueError(
                f"ML-KEM-768 decapsulate: invalid ciphertext length "
                f"{len(ciphertext)}, expected {MLKEM768_CIPHERTEXT_LEN}"
            )

        try:
            with oqs.KeyEncapsulation(KEM_ALG, secret_key=secret_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
        except Exception as exc:
            logger.error("ML-KEM-768 decapsulation failed: %s", exc)
            raise RuntimeError(f"ML-KEM-768 decapsulation failed: {exc}") from exc

        if len(shared_secret) != MLKEM768_SS_LEN:
            raise RuntimeError(
                f"ML-KEM-768 decapsulated secret size mismatch: "
                f"expected {MLKEM768_SS_LEN}, got {len(shared_secret)}"
            )

        logger.debug("ML-KEM-768 decapsulation complete — ss_len=%d", len(shared_secret))
        return shared_secret
