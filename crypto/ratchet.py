from dataclasses import dataclass, field
from crypto.hkdf import derive_ratchet_keys
from config import get_logger

logger = get_logger(__name__)


@dataclass
class RatchetState:
    """
    Holds the symmetric chain ratchet state for a single conversation.

    chain_key: current 32-byte chain key
    step:      number of messages sent or received so far (increments each message)

    LIMITATION: this implementation does not handle out-of-order messages.
    Messages must be decrypted in the exact order they were encrypted.
    This is acceptable for a demo — document it in SECURITY_NOTES.md.
    """
    chain_key: bytes
    step: int = 0


class ChainRatchet:
    """
    Manages ratchet states for all active conversations.

    Each peer gets its own RatchetState. States are kept in memory only —
    they are not persisted to disk or database.
    """

    def __init__(self):
        self._states: dict[str, RatchetState] = {}

    def init_from_session_key(self, peer: str, session_key: bytes) -> None:
        """
        Initialise a ratchet for a peer using the derived session key as root.
        Must be called after handshake completes, before any messages are sent.
        """
        if len(session_key) != 32:
            raise ValueError(f"session_key must be 32 bytes, got {len(session_key)}")
        self._states[peer] = RatchetState(chain_key=session_key, step=0)
        logger.info("Ratchet initialised for peer '%s' at step 0", peer)

    def encrypt_step(self, peer: str) -> tuple[bytes, int]:
        """
        Advance the ratchet and return (message_key, step_used).
        The message_key must be used for AES-256-GCM encryption then discarded.
        """
        state = self._get_state(peer)
        new_chain_key, message_key = derive_ratchet_keys(state.chain_key, state.step)
        current_step = state.step
        state.chain_key = new_chain_key
        state.step += 1
        logger.debug(
            "Ratchet encrypt step %d for peer '%s'", current_step, peer
        )
        return message_key, current_step

    def decrypt_step(self, peer: str, expected_step: int) -> bytes:
        """
        Advance the ratchet to the expected step and return the message_key.
        The message_key must be used for AES-256-GCM decryption then discarded.

        Raises ValueError if the expected_step does not match the current state.
        This enforces in-order message delivery.
        """
        state = self._get_state(peer)
        if state.step != expected_step:
            raise ValueError(
                f"Ratchet step mismatch for peer '{peer}': "
                f"expected step {state.step}, received step {expected_step}. "
                f"Out-of-order messages are not supported."
            )
        new_chain_key, message_key = derive_ratchet_keys(state.chain_key, state.step)
        state.chain_key = new_chain_key
        state.step += 1
        logger.debug(
            "Ratchet decrypt step %d for peer '%s'", expected_step, peer
        )
        return message_key

    def _get_state(self, peer: str) -> RatchetState:
        if peer not in self._states:
            raise KeyError(
                f"No ratchet state for peer '{peer}'. "
                f"Call init_from_session_key() first."
            )
        return self._states[peer]

    def has_state(self, peer: str) -> bool:
        return peer in self._states
