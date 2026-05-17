import logging
import sys
import os

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
LOG_LEVEL  = logging.DEBUG

def configure_logging():
    logging.basicConfig(
        level=LOG_LEVEL,
        format=LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("pqchat.log", mode="a")
        ]
    )

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

# ── Application constants ──────────────────────────────────────────────────────
SECRET_KEY      = os.environ.get("PQCHAT_SECRET", "dev-secret-change-in-production")
DB_PATH         = os.environ.get("PQCHAT_DB", "users.db")
TOKEN_TTL_HOURS = 24

# ── Crypto constants ───────────────────────────────────────────────────────────
KEM_ALG         = "ML-KEM-768"
SIG_ALG         = "ML-DSA-65"
HKDF_INFO       = b"PQChat-v2-session-key"
HKDF_LENGTH     = 32
RATCHET_CHAIN_INFO_PREFIX = b"PQChat-v2-chain-"
RATCHET_MSG_INFO_PREFIX   = b"PQChat-v2-msg-"

# ── Expected key sizes (validate at startup) ───────────────────────────────────
MLKEM768_PUBKEY_LEN     = 1184
MLKEM768_SECKEY_LEN     = 2400
MLKEM768_CIPHERTEXT_LEN = 1088
MLKEM768_SS_LEN         = 32
MLDSA65_PUBKEY_LEN      = 1952
MLDSA65_SECKEY_LEN      = 4032
