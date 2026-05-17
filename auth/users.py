"""
SQLite-backed user store for PQChat v2.0.

Amendment 5: Token expiry = exactly 24 hours UTC.
Passwords hashed with scrypt (n=2**14, r=8, p=1, dklen=64) — ~28ms on Apple Silicon.

Schema:
  users:    username, password_hash, salt, dilithium_public_key,
            ecdh_identity_public_key, created_at
  sessions: token, username, created_at, expires_at (24h UTC)
"""

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = "users.db"
TOKEN_EXPIRY_HOURS = 24  # Amendment 5: exactly 24 hours UTC


# ---------------------------------------------------------------------------
# Database init
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username                 TEXT PRIMARY KEY,
                password_hash            TEXT NOT NULL,
                salt                     TEXT NOT NULL,
                dilithium_public_key     TEXT,
                ecdh_identity_public_key TEXT,
                created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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


def delete_expired_sessions() -> int:
    """
    Remove all expired sessions. Call on app startup and periodically.
    Returns count of deleted rows.
    """
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?", (now,)
        )
        conn.commit()
        return cur.rowcount


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str, salt: str) -> str:
    """
    Hash password with scrypt. Timing: ~28ms @ n=2**14.
    Returns hex string of 64-byte digest.
    """
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        n=2**14, r=8, p=1,
        dklen=64,
    ).hex()


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

def register_user(username: str, password: str) -> bool:
    """
    Register a new user with scrypt-hashed password.

    Returns:
        True on success, False if username already taken.
    """
    if not username or not password:
        return False
    salt = secrets.token_hex(32)
    password_hash = _hash_password(password, salt)
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt),
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already taken


def verify_password(username: str, password: str) -> bool:
    """
    Verify a user's password. Constant-time comparison via secrets.compare_digest.
    Returns False (not raises) if user doesn't exist.
    """
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not row:
        # Still hash to prevent timing-based username enumeration
        _hash_password(password, "0" * 32)
        return False

    stored_hash, salt = row
    computed = _hash_password(password, salt)
    return secrets.compare_digest(stored_hash, computed)


# ---------------------------------------------------------------------------
# Session management (Amendment 5: 24h UTC expiry)
# ---------------------------------------------------------------------------

def create_session(username: str) -> str:
    """
    Create a new session token for the user.

    Amendment 5: Token expires exactly 24 hours from creation (UTC).

    Returns:
        64-char hex token string
    """
    token = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=TOKEN_EXPIRY_HOURS)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token, username, now.isoformat(), expires_at.isoformat()),
        )
        conn.commit()
    return token


def validate_token(token: str | None) -> str | None:
    """
    Validate a session token.

    Returns:
        username if token exists and is not expired
        None if token is missing, invalid, or expired (Amendment 5)
    """
    if not token:
        return None

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token = ?",
            (token,),
        ).fetchone()

    if not row:
        return None

    username, expires_at_str = row

    # Amendment 5: strict UTC expiry check
    expires_at = datetime.fromisoformat(expires_at_str)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    if now > expires_at:
        # Clean up expired token immediately
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        return None

    return username


def invalidate_token(token: str) -> None:
    """Explicitly invalidate a token (logout)."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


# ---------------------------------------------------------------------------
# Public key registry
# ---------------------------------------------------------------------------

def register_public_key(
    username: str,
    dilithium_pubkey_hex: str,
    ecdh_pubkey_hex: str,
) -> None:
    """
    Store a user's ML-DSA-65 and ECDHE identity public keys.
    Public keys are stored as hex strings.
    Called after login when the client sends 'register_identity'.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET dilithium_public_key = ?, "
            "ecdh_identity_public_key = ? WHERE username = ?",
            (dilithium_pubkey_hex, ecdh_pubkey_hex, username),
        )
        conn.commit()


def get_public_keys(username: str) -> dict | None:
    """
    Fetch a user's registered public identity keys.

    Returns:
        {
            "dilithium_public_key":     hex string (ML-DSA-65, 1952 bytes → 3904 hex chars),
            "ecdh_identity_public_key": hex string (P-256 DER)
        }
        None if user not found or keys not yet registered.
    """
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT dilithium_public_key, ecdh_identity_public_key "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not row or not row[0]:
        return None

    return {
        "dilithium_public_key":     row[0],
        "ecdh_identity_public_key": row[1] if row[1] else None,
    }


def user_exists(username: str) -> bool:
    """Check if a username is registered."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row is not None
