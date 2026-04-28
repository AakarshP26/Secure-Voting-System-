"""
protocol.py — TCP wire protocol helpers (length-prefixed framing).

WHY THIS EXISTS
TCP is a byte stream — it doesn't have message boundaries. If we just
send a public key with `sock.sendall(pubkey)`, the receiver doesn't
know how many bytes to read for one "message." `recv(1024)` might
return some, all, or even multiple messages mashed together.

SOLUTION: Length-prefixed framing.
Every message is sent as:
    [4-byte big-endian length] [payload]

The receiver reads exactly 4 bytes, decodes the length, then reads
exactly that many bytes. Simple, reliable, language-agnostic.

This is the same idea used in HTTP/2, gRPC, and many other protocols.
"""

import socket
import struct


# Maximum allowed message size (sanity guard against malicious senders
# claiming a 4 GB message). 16 MB is plenty for any of our crypto blobs.
MAX_MSG_SIZE = 16 * 1024 * 1024


def send_msg(conn: socket.socket, data: bytes) -> None:
    """
    Send a single length-prefixed message over a TCP socket.

    Wire format: [4-byte big-endian unsigned int length] [data bytes]
    """
    if len(data) > MAX_MSG_SIZE:
        raise ValueError(f"Message too large: {len(data)} > {MAX_MSG_SIZE}")

    # struct.pack('!I', n) → 4-byte big-endian unsigned int.
    # '!' = network byte order (big-endian, the standard for protocols).
    # 'I' = unsigned 32-bit integer.
    length_prefix = struct.pack("!I", len(data))
    conn.sendall(length_prefix + data)


def recv_msg(conn: socket.socket) -> bytes:
    """
    Receive a single length-prefixed message from a TCP socket.

    Blocks until the full message is received.
    Raises ConnectionError if the peer disconnects mid-message.
    """
    # First, read exactly 4 bytes for the length.
    length_prefix = _recv_exact(conn, 4)
    (length,) = struct.unpack("!I", length_prefix)

    if length > MAX_MSG_SIZE:
        raise ValueError(f"Peer announced oversized message: {length}")

    # Then read exactly `length` bytes for the payload.
    return _recv_exact(conn, length)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    """
    Read exactly `n` bytes from the socket, looping until done.

    Plain conn.recv(n) might return fewer bytes than requested
    (e.g., if the data is split across multiple TCP packets), so
    we loop until we've accumulated the full n bytes or the peer
    disconnects.
    """
    chunks = []
    bytes_remaining = n
    while bytes_remaining > 0:
        chunk = conn.recv(bytes_remaining)
        if not chunk:
            # Empty bytes means the other side closed the connection.
            raise ConnectionError(
                f"Peer disconnected after {n - bytes_remaining}/{n} bytes"
            )
        chunks.append(chunk)
        bytes_remaining -= len(chunk)
    return b"".join(chunks)