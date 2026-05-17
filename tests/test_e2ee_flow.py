# tests/test_e2ee_flow.py
# Full Alice-Bob handshake simulation at the Python layer.
# Tests that the crypto primitives work end-to-end.

import pytest
import os
from config import configure_logging
configure_logging()

from crypto.kyber     import KyberKEM
from crypto.dilithium import DilithiumSigner
from crypto.hkdf      import derive_session_key
from crypto.ratchet   import ChainRatchet
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key, ECDH, SECP256R1
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class TestFullE2EEHandshake:
    """
    Simulates the complete Alice-Bob handshake at the Python layer.
    This validates that the crypto building blocks compose correctly.
    """

    def test_full_handshake_session_keys_match(self):
        kem    = KyberKEM()
        signer = DilithiumSigner()

        # ── Identity keys ────────────────────────────────────────────────────
        alice_dil_pub, alice_dil_sec = signer.generate_keypair()
        bob_dil_pub,   bob_dil_sec   = signer.generate_keypair()

        # ── Alice generates ephemeral keys ───────────────────────────────────
        alice_kyber_pub, alice_kyber_sec = kem.generate_keypair()
        alice_ecdh_priv  = generate_private_key(SECP256R1(), default_backend())
        alice_ecdh_pub   = alice_ecdh_priv.public_key()

        # ── Alice signs her bundle ───────────────────────────────────────────
        timestamp = b"1700000000000"
        payload   = (
            alice_kyber_pub +
            alice_ecdh_pub.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            ) +
            timestamp
        )
        alice_sig = signer.sign(alice_dil_sec, payload)
        assert signer.verify(alice_dil_pub, payload, alice_sig), \
            "Alice's handshake signature should verify"

        # ── Bob verifies Alice and encapsulates ──────────────────────────────
        assert signer.verify(alice_dil_pub, payload, alice_sig)

        ct, bob_kyber_ss = kem.encapsulate(alice_kyber_pub)

        bob_ecdh_priv  = generate_private_key(SECP256R1(), default_backend())
        bob_ecdh_pub   = bob_ecdh_priv.public_key()
        bob_ecdhe_ss   = bob_ecdh_priv.exchange(ECDH(), alice_ecdh_pub)

        bob_session_key = derive_session_key(
            bob_kyber_ss, bob_ecdhe_ss,
            alice_kyber_pub, alice_kyber_pub  # placeholder for salt
        )

        # ── Alice decapsulates ───────────────────────────────────────────────
        alice_kyber_ss  = kem.decapsulate(alice_kyber_sec, ct)
        assert alice_kyber_ss == bob_kyber_ss, "Kyber shared secrets must match"

        alice_ecdhe_ss  = alice_ecdh_priv.exchange(ECDH(), bob_ecdh_pub)
        assert alice_ecdhe_ss == bob_ecdhe_ss, "ECDH shared secrets must match"

        alice_session_key = derive_session_key(
            alice_kyber_ss, alice_ecdhe_ss,
            alice_kyber_pub, alice_kyber_pub
        )

        assert alice_session_key == bob_session_key, \
            "Session keys must match between Alice and Bob"

    def test_ratchet_encrypt_decrypt_20_messages(self):
        session_key = os.urandom(32)
        alice = ChainRatchet()
        bob   = ChainRatchet()
        alice.init_from_session_key("bob", session_key)
        bob.init_from_session_key("alice", session_key)

        plaintext = "Hello, post-quantum world! Message #{}"
        for i in range(20):
            # Alice encrypts
            msg_key_enc, step = alice.encrypt_step("bob")
            aes_enc = AESGCM(msg_key_enc)
            nonce   = os.urandom(12)
            ct      = aes_enc.encrypt(nonce, plaintext.format(i).encode(), None)

            # Bob decrypts
            msg_key_dec = bob.decrypt_step("alice", step)
            assert msg_key_enc == msg_key_dec, f"Key mismatch at step {i}"
            aes_dec   = AESGCM(msg_key_dec)
            recovered = aes_dec.decrypt(nonce, ct, None).decode()
            assert recovered == plaintext.format(i), \
                f"Decrypted message mismatch at step {i}"

    def test_tampered_ciphertext_fails_aes_gcm(self):
        session_key = os.urandom(32)
        alice = ChainRatchet()
        bob   = ChainRatchet()
        alice.init_from_session_key("bob", session_key)
        bob.init_from_session_key("alice", session_key)

        msg_key_enc, step = alice.encrypt_step("bob")
        aes = AESGCM(msg_key_enc)
        nonce = os.urandom(12)
        ct    = bytearray(aes.encrypt(nonce, b"secret message", None))
        ct[0] ^= 0xFF  # flip a bit

        msg_key_dec = bob.decrypt_step("alice", step)
        aes_dec = AESGCM(msg_key_dec)
        with pytest.raises(Exception):
            aes_dec.decrypt(nonce, bytes(ct), None)
