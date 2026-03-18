import hashlib
import secrets


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


USERS = {
    "alice": _hash_password("alice123"),
    "bob": _hash_password("bob123"),
}

# token -> {"username": str, "session_key": bytes | None}
SESSIONS = {}


def generate_token(username: str) -> str:
    token = secrets.token_hex(32)
    SESSIONS[token] = {"username": username, "session_key": None}
    return token


def validate_token(token: str | None) -> str | None:
    if not token:
        return None
    session = SESSIONS.get(token)
    if not session:
        return None
    return session["username"]


def set_session_key(token: str, key: bytes) -> None:
    if token in SESSIONS:
        SESSIONS[token]["session_key"] = key


def get_session_key(token: str) -> bytes | None:
    session = SESSIONS.get(token)
    if not session:
        return None
    return session["session_key"]


def verify_user(username: str, password: str) -> bool:
    stored_hash = USERS.get(username)
    if not stored_hash:
        return False
    return stored_hash == _hash_password(password)
