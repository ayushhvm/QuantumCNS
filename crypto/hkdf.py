"""
HKDF key derivation functions for PQChat v2.0.

Construction for session keys:
  IKM  = kyber_shared_secret || ecdhe_shared_secret
  Salt = SHA256( lexi_min(alice_kyber_pub, bob_kyber_pub)
              || lexi_max(alice_kyber_pub, bob_kyber_pub) )
  Info = b"PQChat-v2-session-key"
  Len  = 32 bytes (AES-256 key)

Amendment (1): Lexicographic key ordering in HKDF salt.
  Both initiator and responder sort alice/bob pubkeys the same way before hashing,
  so the salt is identical regardless of which side computes it.
  Without this, Alice and Bob derive DIFFERENT session keys silently.

Ratchet key derivation follows the symmetric-ratchet spec:
  Given chain_key[n]:
    chain_key[n+1] = HKDF(ikm=chain_key[n], info=b"PQChat-v2-chain-key")
    message_key[n] = HKDF(ikm=chain_key[n], info=b"PQChat-v2-message-key")
  Both derived from the same chain_key to keep them independent.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _lexicographic_sorted_pubkeys(
    pubkey_a: bytes,
    pubkey_b: bytes,
) -> tuple[bytes, bytes]:
    """
    Return (smaller, larger) lexicographically.

    Amendment (1): Enforces consistent key ordering for HKDF salt computation.
    Both sides of the handshake call this function independently and arrive at
    the same salt, even though one side is the initiator and the other responder.
    """
    if pubkey_a <= pubkey_b:
        return pubkey_a, pubkey_b
    return pubkey_b, pubkey_a


def derive_session_key(
    kyber_secret: bytes,
    ecdhe_secret: bytes,
    kyber_pubkey_a: bytes,
    kyber_pubkey_b: bytes,
) -> bytes:
    """
    Derive a 32-byte AES-256-GCM session key from two shared secrets.

    Args:
        kyber_secret:   shared secret from Kyber768 KEM (32 bytes)
        ecdhe_secret:   shared secret from ECDHE P-256 (32 bytes)
        kyber_pubkey_a: Alice's Kyber768 ephemeral public key (1184 bytes)
        kyber_pubkey_b: Bob's Kyber768 ephemeral public key (1184 bytes)

    Returns:
        32-byte symmetric session key suitable for AES-256-GCM

    HKDF construction:
        IKM  = kyber_secret || ecdhe_secret
        Salt = SHA256(lex_min(pub_a, pub_b) || lex_max(pub_a, pub_b))
        Info = b"PQChat-v2-session-key"
    """
    ikm = kyber_secret + ecdhe_secret

    # Amendment (1): lexicographic ordering — same result regardless of call order
    small, large = _lexicographic_sorted_pubkeys(kyber_pubkey_a, kyber_pubkey_b)
    salt = hashlib.sha256(small + large).digest()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"PQChat-v2-session-key",
    )
    return hkdf.derive(ikm)


def derive_ratchet_keys(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    Advance the symmetric ratchet by one step.

    Derives next chain key and a one-time message key from the current chain key.
    The message key must be used for exactly one AES-GCM encryption and then discarded.

    Args:
        chain_key: current 32-byte chain key

    Returns:
        (new_chain_key, message_key) — both 32 bytes
        new_chain_key: replaces chain_key in ratchet state
        message_key:   use once for AES-GCM, then DELETE

    Forward secrecy guarantee:
        Knowing new_chain_key does not reveal message_key,
        and knowing message_key does not reveal chain_key.
        Both are derived from chain_key but with different info strings.
    """
    hkdf_chain = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PQChat-v2-chain-key",
    )
    hkdf_msg = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PQChat-v2-message-key",
    )
    new_chain_key = hkdf_chain.derive(chain_key)
    message_key = hkdf_msg.derive(chain_key)
    return new_chain_key, message_key


def compute_fingerprint(pubkey_a: bytes, pubkey_b: bytes) -> str:
    """
    Compute a 24-hex-char safety number for out-of-band key verification.

    Construction: SHA256(lex_min || lex_max)[:12] → 24 hex chars
    Displayed as: XXXX XXXX XXXX XXXX XXXX XXXX (6 groups of 4)

    Uses lexicographic ordering so Alice and Bob compute the same fingerprint.

    Args:
        pubkey_a: Alice's ML-DSA-65 identity public key
        pubkey_b: Bob's ML-DSA-65 identity public key

    Returns:
        24-character hex string with spaces every 4 chars
    """
    small, large = _lexicographic_sorted_pubkeys(pubkey_a, pubkey_b)
    digest = hashlib.sha256(small + large).digest()[:12]  # 12 bytes = 24 hex chars
    hex_str = digest.hex()
    return " ".join(hex_str[i:i+4] for i in range(0, 24, 4))
