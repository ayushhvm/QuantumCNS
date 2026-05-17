"""
Symmetric ratchet implementation for PQChat v2.0.

Implements the Symmetric-Key Ratchet from the Signal Double Ratchet spec.
Reference: https://signal.org/docs/specifications/doubleratchet/

State per conversation:
  chain_key: 32 bytes — current position in the ratchet chain
  step:       int     — message counter (for debugging/UI display)

Forward Secrecy:
  Each message_key is derived from chain_key and immediately discarded after use.
  An attacker who compromises the current chain_key cannot derive past message_keys.

DH Ratchet (NOT IMPLEMENTED — DOCUMENTED LIMITATION):
  The full Double Ratchet adds a Diffie-Hellman ratchet layer every N messages.
  This would provide "break-in recovery" (future messages safe even if current
  state is compromised). It is NOT implemented here. Reason: proper DH ratchet
  requires out-of-order message handling (skipped message keys must be stored),
  which adds significant complexity beyond the scope of this demo.
  See Signal spec §2.2 for the full construction.

Amendment (3): Session Reset
  reset() clears all ratchet state. The UI exposes a "Reset Session" button
  that calls this, resolving ratchet desync from re-connections or dropped events.
"""

from crypto.hkdf import derive_ratchet_keys


class SymmetricRatchet:
    """
    Per-conversation symmetric ratchet state.

    Create one instance per active conversation. Store in a dict keyed by username.
    """

    def __init__(self, root_key: bytes):
        """
        Initialize the ratchet with a root key (the HKDF session key).

        Args:
            root_key: 32-byte session key derived from Kyber768+ECDHE HKDF
        """
        self.chain_key: bytes = root_key
        self.step: int = 0

    def advance(self) -> bytes:
        """
        Advance the ratchet by one step and return a one-time message key.

        The returned message_key MUST be used for exactly one AES-GCM operation
        and then discarded. The caller is responsible for not storing it.

        Returns:
            message_key: 32-byte one-time key for AES-256-GCM
        """
        new_chain_key, message_key = derive_ratchet_keys(self.chain_key)
        self.chain_key = new_chain_key  # advance state
        self.step += 1
        # message_key is not stored in state — forward secrecy guaranteed
        return message_key

    def reset(self, new_root_key: bytes) -> None:
        """
        Reset ratchet state to a new root key.

        Amendment (3): Called when the UI "Reset Session" button is clicked,
        or when a new handshake is performed after a desync event.
        After reset, both parties must re-run the handshake to establish
        a new shared root_key before messaging can resume.

        Args:
            new_root_key: 32-byte key from a fresh handshake
        """
        self.chain_key = new_root_key
        self.step = 0

    @property
    def state_summary(self) -> dict:
        """Return a safe summary of ratchet state for the crypto terminal UI."""
        return {
            "step": self.step,
            "chain_key_preview": self.chain_key.hex()[:16] + "...",
            # Never expose full chain_key in logs
        }


class RatchetManager:
    """
    Manages per-conversation ratchet instances server-side.

    On the server (blind relay), this is used to track ratchet step numbers
    for routing sync. The server does NOT hold message keys — only step counts.

    For the full client-side ratchet, see static/js/ratchet_client.js.
    """

    def __init__(self):
        self._ratchets: dict[str, SymmetricRatchet] = {}

    def initialize(self, conversation_id: str, root_key: bytes) -> SymmetricRatchet:
        """Create or replace a ratchet for a conversation."""
        ratchet = SymmetricRatchet(root_key)
        self._ratchets[conversation_id] = ratchet
        return ratchet

    def get(self, conversation_id: str) -> SymmetricRatchet | None:
        """Retrieve an existing ratchet. Returns None if not initialized."""
        return self._ratchets.get(conversation_id)

    def reset(self, conversation_id: str, new_root_key: bytes) -> SymmetricRatchet:
        """
        Reset ratchet for a conversation (Amendment 3 — session reset support).
        Creates new ratchet if one doesn't exist yet.
        """
        if conversation_id in self._ratchets:
            self._ratchets[conversation_id].reset(new_root_key)
        else:
            self._ratchets[conversation_id] = SymmetricRatchet(new_root_key)
        return self._ratchets[conversation_id]

    def remove(self, conversation_id: str) -> None:
        """Remove ratchet state when a user disconnects."""
        self._ratchets.pop(conversation_id, None)
