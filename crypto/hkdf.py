import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from config import get_logger, HKDF_INFO, HKDF_LENGTH
from config import RATCHET_CHAIN_INFO_PREFIX, RATCHET_MSG_INFO_PREFIX

logger = get_logger(__name__)


def derive_session_key(
    kyber_shared_secret: bytes,
    ecdhe_shared_secret: bytes,
    alice_kyber_pubkey: bytes,
    bob_kyber_pubkey: bytes,
) -> bytes:
    """
    Derive a 32-byte AES-256-GCM session key from the hybrid shared secrets.

    Construction (fixed — do not alter ordering):
        IKM  = kyber_shared_secret || ecdhe_shared_secret
        Salt = SHA256(alice_kyber_pubkey || bob_kyber_pubkey)
        Info = b"PQChat-v2-session-key"
        Len  = 32 bytes

    The salt binds the derived key to the specific public keys exchanged,
    preventing key reuse across sessions.
    """
    ikm  = kyber_shared_secret + ecdhe_shared_secret
    salt = hashlib.sha256(alice_kyber_pubkey + bob_kyber_pubkey).digest()

    logger.debug(
        "HKDF-SHA256 session key derivation — ikm_len=%d, salt_len=%d, output=32",
        len(ikm), len(salt)
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_LENGTH,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(ikm)


def derive_ratchet_keys(chain_key: bytes, step: int) -> tuple[bytes, bytes]:
    """
    Advance the symmetric chain ratchet one step.

    Returns (new_chain_key, message_key).

    The message_key must be used immediately and discarded.
    The chain_key is updated to new_chain_key for the next step.
    Deriving both from the same chain_key (not sequentially) ensures
    that the message key cannot be re-derived from the new chain key.
    """
    if len(chain_key) != 32:
        raise ValueError(f"chain_key must be 32 bytes, got {len(chain_key)}")

    step_bytes = step.to_bytes(4, "big")

    hkdf_chain = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=RATCHET_CHAIN_INFO_PREFIX + step_bytes,
    )
    hkdf_msg = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=RATCHET_MSG_INFO_PREFIX + step_bytes,
    )

    new_chain_key = hkdf_chain.derive(chain_key)
    message_key   = hkdf_msg.derive(chain_key)

    logger.debug(
        "Ratchet step %d — new chain_key derived, message_key derived and returned",
        step
    )
    return new_chain_key, message_key
