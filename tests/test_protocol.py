"""
test_protocol.py — Unit tests for the TCP wire-protocol helpers.

Covers: send_msg, recv_msg, _recv_exact in utils/protocol.py.

All tests use socket.socketpair() to create a connected loopback pair
without needing a real network or server process.

Run with:
    pytest tests/test_protocol.py -v
"""

import os
import socket
import struct
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils.protocol import send_msg, recv_msg, MAX_MSG_SIZE


def _make_socket_pair():
    """Return a connected (sender, receiver) socket pair."""
    return socket.socketpair()


# ---------------------------------------------------------------------------
# Basic send / recv round-trips
# ---------------------------------------------------------------------------

def test_send_recv_roundtrip():
    """Payload sent on one side must arrive intact on the other."""
    a, b = _make_socket_pair()
    try:
        data = b"Vote: Alice"
        send_msg(a, data)
        assert recv_msg(b) == data
    finally:
        a.close()
        b.close()


def test_send_recv_empty_payload():
    """GCM can produce zero-byte ciphertexts; the framing layer must handle them."""
    a, b = _make_socket_pair()
    try:
        send_msg(a, b"")
        assert recv_msg(b) == b""
    finally:
        a.close()
        b.close()


def test_send_recv_binary_data():
    """Non-UTF-8 binary blobs (e.g. public keys) must survive the wire."""
    a, b = _make_socket_pair()
    try:
        data = bytes(range(256))
        send_msg(a, data)
        assert recv_msg(b) == data
    finally:
        a.close()
        b.close()


def test_send_recv_large_payload():
    """Payloads larger than a single TCP segment must be reassembled correctly."""
    a, b = _make_socket_pair()
    try:
        data = os.urandom(64 * 1024)  # 64 KB
        send_msg(a, data)
        assert recv_msg(b) == data
    finally:
        a.close()
        b.close()


def test_multiple_messages_in_sequence():
    """Sending several messages back-to-back must not corrupt boundaries."""
    a, b = _make_socket_pair()
    try:
        messages = [b"first", b"second", b"third", b""]
        for msg in messages:
            send_msg(a, msg)
        for expected in messages:
            assert recv_msg(b) == expected
    finally:
        a.close()
        b.close()


def test_bidirectional_exchange():
    """Both sides can send and receive in an interleaved conversation."""
    a, b = _make_socket_pair()
    try:
        send_msg(a, b"ping")
        assert recv_msg(b) == b"ping"
        send_msg(b, b"pong")
        assert recv_msg(a) == b"pong"
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

def test_wire_format_is_4_byte_big_endian_length_prefix():
    """send_msg must prepend a 4-byte big-endian unsigned int length."""
    a, b = _make_socket_pair()
    try:
        payload = b"hello"
        send_msg(a, payload)
        # Read the raw bytes on the other side without using recv_msg.
        raw = b""
        while len(raw) < 4 + len(payload):
            raw += b.recv(1024)
        length = struct.unpack("!I", raw[:4])[0]
        assert length == len(payload)
        assert raw[4:] == payload
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

def test_send_oversized_message_raises_value_error():
    """Messages larger than MAX_MSG_SIZE must be rejected before any I/O."""
    a, b = _make_socket_pair()
    try:
        with pytest.raises(ValueError, match="too large"):
            send_msg(a, b"x" * (MAX_MSG_SIZE + 1))
    finally:
        a.close()
        b.close()


def test_recv_on_closed_peer_raises_connection_error():
    """If the peer closes the connection before sending a full message,
    recv_msg must raise ConnectionError rather than silently return partial data."""
    a, b = _make_socket_pair()
    # Close b immediately — a has nothing to read.
    b.close()
    try:
        with pytest.raises(ConnectionError):
            recv_msg(a)
    finally:
        a.close()


def test_recv_peer_closes_mid_message_raises_connection_error():
    """If the peer closes the connection after sending the length prefix but
    before the full payload, recv_msg must raise ConnectionError."""
    a, b = _make_socket_pair()
    try:
        # Send a length header claiming 100 bytes, then close without the payload.
        a.sendall(struct.pack("!I", 100))
        a.close()
        with pytest.raises(ConnectionError):
            recv_msg(b)
    finally:
        b.close()


def test_recv_crafted_oversized_length_raises_value_error():
    """A malicious peer that sends an oversized length header must be rejected."""
    a, b = _make_socket_pair()
    try:
        # Craft a length header that exceeds MAX_MSG_SIZE.
        a.sendall(struct.pack("!I", MAX_MSG_SIZE + 1))
        a.close()
        with pytest.raises(ValueError, match="oversized"):
            recv_msg(b)
    finally:
        b.close()


# ---------------------------------------------------------------------------
# Concurrency — send from one thread, receive from another
# ---------------------------------------------------------------------------

def test_concurrent_send_recv():
    """send_msg and recv_msg must work correctly across threads."""
    a, b = _make_socket_pair()
    payload = os.urandom(8192)
    result = {}

    def sender():
        send_msg(a, payload)
        a.close()

    def receiver():
        result["data"] = recv_msg(b)
        b.close()

    t1 = threading.Thread(target=sender)
    t2 = threading.Thread(target=receiver)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert result.get("data") == payload
