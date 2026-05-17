import pytest
import os
import sqlite3
import tempfile

# Use a temporary DB for tests — never touch production users.db
os.environ["PQCHAT_DB"] = tempfile.mktemp(suffix=".db")

from config import configure_logging
configure_logging()

from auth.users  import init_db, register_user, verify_password, \
                         register_public_keys, get_public_keys, user_exists
from auth.tokens import generate_token, validate_token, revoke_token


@pytest.fixture(autouse=True)
def fresh_db():
    """Re-initialise the database before each test."""
    with sqlite3.connect(os.environ["PQCHAT_DB"]) as conn:
        conn.execute("DROP TABLE IF EXISTS users")
        conn.execute("DROP TABLE IF EXISTS sessions")
        conn.commit()
    init_db()
    yield


class TestUserRegistration:

    def test_register_success(self):
        assert register_user("alice", "password123") is True

    def test_register_duplicate_fails(self):
        register_user("alice", "password123")
        assert register_user("alice", "other") is False

    def test_register_different_users(self):
        assert register_user("alice", "pw") is True
        assert register_user("bob",   "pw") is True

    def test_user_exists_after_register(self):
        register_user("alice", "pw")
        assert user_exists("alice") is True

    def test_user_not_exists(self):
        assert user_exists("nobody") is False


class TestPasswordVerification:

    def test_correct_password(self):
        register_user("alice", "correct_password")
        assert verify_password("alice", "correct_password") is True

    def test_wrong_password(self):
        register_user("alice", "correct_password")
        assert verify_password("alice", "wrong_password") is False

    def test_nonexistent_user(self):
        assert verify_password("nobody", "anything") is False


class TestPublicKeys:

    def test_register_and_retrieve_keys(self):
        register_user("alice", "pw")
        dil_pub  = os.urandom(1952)  # fake key, right size
        ecdh_pub = os.urandom(65)
        register_public_keys("alice", dil_pub, ecdh_pub)

        keys = get_public_keys("alice")
        assert keys is not None
        assert keys["dilithium_public_key"] == dil_pub.hex()
        assert keys["ecdh_public_key"]      == ecdh_pub.hex()

    def test_keys_not_registered_returns_none(self):
        register_user("alice", "pw")
        assert get_public_keys("alice") is None

    def test_nonexistent_user_returns_none(self):
        assert get_public_keys("nobody") is None


class TestTokens:

    def test_generate_and_validate(self):
        register_user("alice", "pw")
        token = generate_token("alice")
        assert validate_token(token) == "alice"

    def test_invalid_token(self):
        assert validate_token("not-a-real-token") is None

    def test_revoked_token(self):
        register_user("alice", "pw")
        token = generate_token("alice")
        revoke_token(token)
        assert validate_token(token) is None
