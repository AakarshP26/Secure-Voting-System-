"""
router.py — Thread-safe routing table for active chat connections.

Maintains a mapping of username -> (socket, aes_key) so that messages
can be forwarded between clients connected on different threads.
"""

import threading
import socket
from typing import Optional

_lock = threading.RLock()
# Maps username -> (connection, aes_key)
_active_connections: dict[str, tuple[socket.socket, bytes]] = {}


def register(username: str, conn: socket.socket, aes_key: bytes) -> None:
    """Register a user's active connection and session key."""
    with _lock:
        _active_connections[username] = (conn, aes_key)


def unregister(username: str) -> None:
    """Remove a user's active connection."""
    with _lock:
        _active_connections.pop(username, None)


def get_connection(username: str) -> Optional[tuple[socket.socket, bytes]]:
    """Retrieve the socket and AES key for an active user, if online."""
    with _lock:
        return _active_connections.get(username)

def get_online_users() -> list[str]:
    """Get a list of currently online users."""
    with _lock:
        return list(_active_connections.keys())
