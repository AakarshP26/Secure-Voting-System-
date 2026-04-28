"""
test_client.py — Unit tests for the voter-client helpers.

Covers:
  - CANDIDATES dictionary
  - get_vote_from_user  (interactive ballot — stdin is monkeypatched)
  - cast_vote           (full secure-vote flow — server runs in a thread)

cast_vote tests start a minimal one-shot server on a dynamically chosen
free port so that tests never conflict with a running server or each other.

Run with:
    pytest tests/test_client.py -v
"""

import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import client as client_module
from client import CANDIDATES, get_vote_from_user, cast_vote
import server as server_module
from server import handle_client


# ---------------------------------------------------------------------------
# Fixture: reset tally between tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_tally():
    with server_module._tally_lock:
        server_module._tally.clear()
    yield
    with server_module._tally_lock:
        server_module._tally.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Return an OS-assigned free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_one_shot_server(mode: str, port: int) -> threading.Thread:
    """
    Start a server that accepts exactly one connection, handles it with
    handle_client, then exits.  The server socket is created before the
    thread starts so the port is bound and ready by the time the caller
    can connect.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(15)

    def _run():
        try:
            conn, addr = srv.accept()
            handle_client(conn, addr, mode)
        finally:
            srv.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# CANDIDATES
# ---------------------------------------------------------------------------

def test_candidates_is_non_empty():
    assert len(CANDIDATES) > 0


def test_candidates_keys_are_strings():
    for k in CANDIDATES:
        assert isinstance(k, str)


def test_candidates_values_are_strings():
    for v in CANDIDATES.values():
        assert isinstance(v, str)


def test_candidates_contains_expected_names():
    names = set(CANDIDATES.values())
    assert "Alice" in names
    assert "Bob" in names
    assert "Charlie" in names


# ---------------------------------------------------------------------------
# get_vote_from_user
# ---------------------------------------------------------------------------

def test_get_vote_from_user_valid_choice(monkeypatch):
    """A valid numeric input must return the corresponding candidate name."""
    first_key = next(iter(CANDIDATES))
    monkeypatch.setattr("builtins.input", lambda _: first_key)
    result = get_vote_from_user()
    assert result == CANDIDATES[first_key]


def test_get_vote_from_user_all_valid_choices(monkeypatch):
    """Every valid key maps to its candidate."""
    for key, name in CANDIDATES.items():
        monkeypatch.setattr("builtins.input", lambda _, k=key: k)
        assert get_vote_from_user() == name


def test_get_vote_from_user_invalid_then_valid(monkeypatch):
    """
    get_vote_from_user loops until a valid choice is entered.
    Simulate one bad input followed by a valid one.
    """
    valid_key = next(iter(CANDIDATES))
    inputs = iter(["99", "bad", valid_key])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    result = get_vote_from_user()
    assert result == CANDIDATES[valid_key]


def test_get_vote_from_user_strips_whitespace(monkeypatch):
    """Leading/trailing whitespace in input must be stripped before lookup."""
    valid_key = next(iter(CANDIDATES))
    monkeypatch.setattr("builtins.input", lambda _: f"  {valid_key}  ")
    result = get_vote_from_user()
    assert result == CANDIDATES[valid_key]


# ---------------------------------------------------------------------------
# cast_vote — full round-trip tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def patched_port(monkeypatch):
    """
    Redirect cast_vote to an ephemeral port so it never collides with
    the real server or other test runs.
    """
    port = _free_port()
    monkeypatch.setattr(client_module, "PORT", port)
    return port


def test_cast_vote_ml_kem_returns_metrics(patched_port):
    """cast_vote must return a metrics dict with the expected keys."""
    mode = "ml_kem"
    vote = "Alice"
    t = _start_one_shot_server(mode, patched_port)

    metrics = cast_vote(mode, vote, quiet=True)
    t.join(timeout=15)

    expected_keys = {
        "mode", "vote", "connect_ms", "handshake_ms",
        "encrypt_send_ms", "ack_ms", "total_ms",
        "bytes_sent_app", "bytes_received_app",
    }
    assert expected_keys.issubset(metrics.keys())


def test_cast_vote_ml_kem_records_correct_vote(patched_port):
    """cast_vote must result in the server recording the correct candidate."""
    mode = "ml_kem"
    vote = "Bob"
    t = _start_one_shot_server(mode, patched_port)

    cast_vote(mode, vote, quiet=True)
    t.join(timeout=15)

    assert server_module._tally[vote] == 1


def test_cast_vote_hybrid_roundtrip(patched_port):
    """cast_vote also works with hybrid key exchange."""
    mode = "hybrid"
    vote = "Charlie"
    t = _start_one_shot_server(mode, patched_port)

    metrics = cast_vote(mode, vote, quiet=True)
    t.join(timeout=15)

    assert metrics["vote"] == vote
    assert metrics["mode"] == mode
    assert server_module._tally[vote] == 1


def test_cast_vote_timings_are_non_negative(patched_port):
    """All timing metrics must be ≥ 0."""
    t = _start_one_shot_server("ml_kem", patched_port)
    metrics = cast_vote("ml_kem", "Alice", quiet=True)
    t.join(timeout=15)

    for timing_key in ("connect_ms", "handshake_ms", "encrypt_send_ms",
                       "ack_ms", "total_ms"):
        assert metrics[timing_key] >= 0, f"{timing_key} was negative"


def test_cast_vote_bytes_sent_is_positive(patched_port):
    """At minimum the mode marker and encrypted vote are sent."""
    t = _start_one_shot_server("ml_kem", patched_port)
    metrics = cast_vote("ml_kem", "Alice", quiet=True)
    t.join(timeout=15)

    assert metrics["bytes_sent_app"] > 0
    assert metrics["bytes_received_app"] > 0


def test_cast_vote_connection_refused_raises_system_exit(monkeypatch):
    """If no server is listening, cast_vote raises ConnectionRefusedError."""
    # Use a port that is almost certainly not listening.
    monkeypatch.setattr(client_module, "PORT", _free_port())
    with pytest.raises(ConnectionRefusedError):
        cast_vote("ml_kem", "Alice", quiet=True)
