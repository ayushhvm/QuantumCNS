import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from config import get_logger, DB_PATH, TOKEN_TTL_HOURS

logger = get_logger(__name__)


def generate_token(username: str) -> str:
    """
    Create a session token for a user and store it in the database.
    Returns the token string.
    """
    token      = secrets.token_hex(32)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=TOKEN_TTL_HOURS)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token, username, created_at.isoformat(), expires_at.isoformat())
        )
        conn.commit()

    logger.debug("Token generated for %s — expires_at=%s", username, expires_at)
    return token


def validate_token(token: str) -> str | None:
    """
    Validate a session token.
    Returns username if valid and not expired, None otherwise.
    """
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token=?",
            (token,)
        ).fetchone()

    if not row:
        return None

    username, expires_at_str = row
    expires_at = datetime.fromisoformat(expires_at_str)

    if datetime.now(timezone.utc) > expires_at:
        logger.warning("Expired token used by %s", username)
        return None

    return username


def revoke_token(token: str) -> None:
    """Delete a session token (logout)."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
    logger.debug("Token revoked")
