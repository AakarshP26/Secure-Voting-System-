"""
protocol.py — Structured JSON message schema for the secure chat backend.

WHY THIS EXISTS
---------------
Previously the system sent raw UTF-8 strings (e.g. "Alice") as the
AES-GCM payload. That approach has no metadata: no message identity,
no timestamp, no sender/recipient, no type routing, no replay protection.

This module defines and validates the canonical JSON schema for every
message that flows through the secure pipe, so that:
  - The server can route messages (type field)
  - Replay protection can work (message_id field)
  - Time-window validation is possible (timestamp field)
  - The UI can display correct metadata (from, to, data fields)

WIRE FORMAT (unchanged)
-----------------------
The JSON payload is serialised to UTF-8, then encrypted as AES-256-GCM
by aes.py. The framing in utils/protocol.py (4-byte length prefix) is
also unchanged. This module only governs what is inside the AES envelope.

Author: Aakarsh Prabhu
"""

import json
import secrets
import time
from typing import Optional


# ------------------------------------------------------------------
# Message types
# ------------------------------------------------------------------

class MsgType:
    CHAT    = "chat"
    AUTH    = "auth"
    ACK     = "ack"
    ERROR   = "error"
    SYSTEM  = "system"


# ------------------------------------------------------------------
# Error codes
# ------------------------------------------------------------------

class ErrCode:
    AUTH_FAILED    = "AUTH_FAILED"
    REPLAY         = "REPLAY_DETECTED"
    EXPIRED        = "MESSAGE_EXPIRED"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    MODE_MISMATCH  = "MODE_MISMATCH"
    UNKNOWN        = "UNKNOWN_ERROR"


# ------------------------------------------------------------------
# Builder helpers (construct valid dicts — no serialisation here)
# ------------------------------------------------------------------

def build_chat(sender: str, recipient: str, data: str) -> dict:
    """Build a chat message payload."""
    return {
        "message_id": secrets.token_hex(16),
        "timestamp":  time.time(),
        "type":       MsgType.CHAT,
        "from":       sender,
        "to":         recipient,
        "data":       data,
    }


def build_auth(username: str, password: str) -> dict:
    """Build an authentication payload (sent encrypted, so password is safe)."""
    return {
        "message_id": secrets.token_hex(16),
        "timestamp":  time.time(),
        "type":       MsgType.AUTH,
        "from":       username,
        "to":         "server",
        "data":       password,          # transported inside AES-GCM envelope
    }


def build_ack(message_id: str, status: str = "delivered") -> dict:
    """Build a delivery acknowledgement."""
    return {
        "message_id": secrets.token_hex(16),
        "timestamp":  time.time(),
        "type":       MsgType.ACK,
        "from":       "server",
        "to":         "",
        "data":       "",
        "ref_id":     message_id,        # ID of the message being acknowledged
        "status":     status,            # sent | delivered | read
    }


def build_error(code: str, detail: str = "") -> dict:
    """Build a structured error response."""
    return {
        "message_id": secrets.token_hex(16),
        "timestamp":  time.time(),
        "type":       MsgType.ERROR,
        "from":       "server",
        "to":         "",
        "data":       detail,
        "code":       code,
    }


def build_system(data: str) -> dict:
    """Build a system notification (e.g. key_renegotiation_required)."""
    return {
        "message_id": secrets.token_hex(16),
        "timestamp":  time.time(),
        "type":       MsgType.SYSTEM,
        "from":       "server",
        "to":         "",
        "data":       data,
    }


# ------------------------------------------------------------------
# Serialisation / deserialisation
# ------------------------------------------------------------------

def encode(payload: dict) -> bytes:
    """Serialise a payload dict to UTF-8 JSON bytes (for AES encryption)."""
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode(raw: bytes) -> dict:
    """Deserialise UTF-8 JSON bytes from AES decryption back to a dict."""
    return json.loads(raw.decode("utf-8"))


# ------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------

REQUIRED_FIELDS = {"message_id", "timestamp", "type", "from", "to", "data"}


def validate(payload: dict) -> Optional[str]:
    """
    Validate a decoded payload dict.

    Returns None if valid, or an error string describing the first problem.
    """
    missing = REQUIRED_FIELDS - payload.keys()
    if missing:
        return f"Missing fields: {missing}"

    if not isinstance(payload["message_id"], str) or len(payload["message_id"]) < 16:
        return "message_id must be a hex string of at least 16 characters"

    if not isinstance(payload["timestamp"], (int, float)):
        return "timestamp must be a numeric Unix epoch value"

    if payload["type"] not in vars(MsgType).values():
        return f"Unknown message type: {payload['type']!r}"

    return None  # valid
