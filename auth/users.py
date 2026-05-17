import sqlite3
import hashlib
import secrets
from config import get_logger, DB_PATH

logger = get_logger(__name__)


def init_db() -> None:
    """Create tables if they do not exist. Safe to call on every startup."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username             TEXT PRIMARY KEY,
                password_hash        TEXT NOT NULL,
                salt                 TEXT NOT NULL,
                dilithium_public_key BLOB,
                ecdh_public_key      BLOB,
                created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        conn.commit()
    logger.info("Database initialised — path=%s", DB_PATH)


def register_user(username: str, password: str) -> bool:
    """
    Register a new user with a scrypt-hashed password.
    Returns True on success, False if username is already taken.
    """
    salt = secrets.token_hex(32)
    password_hash = hashlib.scrypt(
        password.encode(),
        salt=salt.encode(),
        n=2**14, r=8, p=1,
        dklen=64
    ).hex()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            conn.commit()
        logger.info("User registered: %s", username)
        return True
    except sqlite3.IntegrityError:
        logger.warning(
            "Registration failed: username '%s' already taken", username
        )
        return False


def verify_password(username: str, password: str) -> bool:
    """
    Verify a user's password using constant-time comparison.
    Returns True if correct, False otherwise.
    """
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if not row:
        logger.warning("Login failed for: %s — user not found", username)
        return False

    stored_hash, salt = row
    computed = hashlib.scrypt(
        password.encode(),
        salt=salt.encode(),
        n=2**14, r=8, p=1,
        dklen=64
    ).hex()

    ok = secrets.compare_digest(stored_hash, computed)
    if ok:
        logger.info("Login successful: %s", username)
    else:
        logger.warning("Login failed for: %s — bad password", username)
    return ok


def register_public_keys(
    username: str,
    dilithium_pubkey: bytes,
    ecdh_pubkey: bytes
) -> None:
    """Store a user's public identity keys. Safe to call on re-registration."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET dilithium_public_key=?, ecdh_public_key=? "
            "WHERE username=?",
            (dilithium_pubkey, ecdh_pubkey, username)
        )
        conn.commit()
    logger.debug(
        "Public key registered for %s — dilithium_pubkey_len=%d bytes, "
        "ecdh_pubkey_len=%d bytes",
        username, len(dilithium_pubkey), len(ecdh_pubkey)
    )


def get_public_keys(username: str) -> dict | None:
    """
    Retrieve a user's registered public keys.
    Returns dict with hex-encoded keys, or None if user not found
    or keys not yet registered.
    """
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT dilithium_public_key, ecdh_public_key "
            "FROM users WHERE username=?",
            (username,)
        ).fetchone()

    if not row or not row[0]:
        return None

    return {
        "dilithium_public_key": row[0].hex(),
        "ecdh_public_key":      row[1].hex() if row[1] else None,
    }


def user_exists(username: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
    return row is not None
