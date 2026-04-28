"""
test_server.py — Unit tests for server-side helper functions.

Covers:
  - _record_vote / _print_tally  (vote tally management)
  - handle_client                (per-connection handler)

handle_client tests use in-process socket pairs and a simulated client
thread so they run without a real network and without starting the full
blocking server loop.

Run with:
    pytest tests/test_server.py -v
"""

import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import server as server_module
from server import _record_vote, _print_tally, handle_client
from crypto.kex_handlers import MLKEMHandler, HybridHandler
from crypto.kdf import derive_aes_key
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from utils.protocol import send_msg, recv_msg


# ---------------------------------------------------------------------------
# Fixture: reset the module-level tally between tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_tally():
    """Clear the shared vote counter before every test."""
    with server_module._tally_lock:
        server_module._tally.clear()
    yield
    with server_module._tally_lock:
        server_module._tally.clear()


# ---------------------------------------------------------------------------
# _record_vote
# ---------------------------------------------------------------------------

def test_record_vote_increments_counter():
    _record_vote("Alice")
    assert server_module._tally["Alice"] == 1


def test_record_vote_multiple_candidates():
    _record_vote("Alice")
    _record_vote("Bob")
    _record_vote("Alice")
    assert server_module._tally["Alice"] == 2
    assert server_module._tally["Bob"] == 1


def test_record_vote_unknown_candidate_is_counted():
    """The server records whatever string it receives — no allow-list filtering."""
    _record_vote("WriteInCandidate")
    assert server_module._tally["WriteInCandidate"] == 1


def test_record_vote_is_thread_safe():
    """100 concurrent threads each cast one vote; the total must be exactly 100."""
    threads = [
        threading.Thread(target=_record_vote, args=("Alice",))
        for _ in range(100)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert server_module._tally["Alice"] == 100


# ---------------------------------------------------------------------------
# _print_tally
# ---------------------------------------------------------------------------

def test_print_tally_empty(capsys):
    _print_tally()
    captured = capsys.readouterr()
    assert "no votes" in captured.out.lower()


def test_print_tally_with_votes(capsys):
    _record_vote("Alice")
    _record_vote("Alice")
    _record_vote("Bob")
    _print_tally()
    captured = capsys.readouterr()
    assert "Alice" in captured.out
    assert "Bob" in captured.out
    # Alice has more votes so should appear first (most_common ordering).
    assert captured.out.index("Alice") < captured.out.index("Bob")


def test_print_tally_shows_counts(capsys):
    _record_vote("Charlie")
    _record_vote("Charlie")
    _record_vote("Charlie")
    _print_tally()
    captured = capsys.readouterr()
    assert "Charlie" in captured.out
    assert "3" in captured.out


# ---------------------------------------------------------------------------
# handle_client helpers
# ---------------------------------------------------------------------------

def _simulate_client_server_exchange(mode, vote, server_mode=None):
    """
    Spin up handle_client in a thread and simulate the full client protocol
    on the other end of an in-process socket pair.

    Parameters
    ----------
    mode : str
        Key-exchange mode string to use for the client simulation.
    vote : str
        Vote string the simulated client will cast (e.g. "Alice").
    server_mode : str | None
        Mode the server expects. Defaults to ``mode``. Pass a different
        value to trigger the mode-mismatch path.

    Returns
    -------
    dict with keys:
        "ack"          – decrypted ACK bytes received by the client (or None)
        "server_error" – exception raised by server thread (or None)
        "client_error" – exception raised by client thread (or None)
    """
    server_mode = server_mode or mode
    server_sock, client_sock = socket.socketpair()
    result = {"ack": None, "server_error": None, "client_error": None}

    def run_server():
        try:
            handle_client(server_sock, ("127.0.0.1", 0), server_mode)
        except Exception as exc:
            result["server_error"] = exc
        finally:
            server_sock.close()

    def run_client():
        try:
            # Step 1: send mode marker
            send_msg(client_sock, mode.encode("utf-8"))

            if mode != server_mode:
                # Mode mismatch — server will close without a valid key exchange.
                # Just read whatever the server sends back and exit.
                try:
                    recv_msg(client_sock)
                except Exception:
                    pass
                return

            # Step 2: key exchange
            if mode == "ml_kem":
                handler = MLKEMHandler()
            elif mode == "hybrid":
                handler = HybridHandler()
            else:
                raise ValueError(f"Unsupported test mode: {mode}")

            shared_secret = handler.client_side(client_sock)

            # Step 3: derive AES key
            aes_key = derive_aes_key(shared_secret)

            # Step 4: send encrypted vote
            ciphertext = aes_encrypt(aes_key, vote.encode("utf-8"))
            send_msg(client_sock, ciphertext)

            # Step 5: receive and decrypt ACK
            ack_blob = recv_msg(client_sock)
            result["ack"] = aes_decrypt(aes_key, ack_blob)
        except Exception as exc:
            result["client_error"] = exc
        finally:
            client_sock.close()

    t_s = threading.Thread(target=run_server, daemon=True)
    t_c = threading.Thread(target=run_client, daemon=True)
    t_s.start()
    t_c.start()
    t_s.join(timeout=15)
    t_c.join(timeout=15)

    return result


# ---------------------------------------------------------------------------
# handle_client — successful flows
# ---------------------------------------------------------------------------

def test_handle_client_ml_kem_sends_ack():
    """Server must reply with an encrypted ACK containing 'ACK'."""
    r = _simulate_client_server_exchange("ml_kem", "Alice")
    assert r["server_error"] is None
    assert r["client_error"] is None
    assert r["ack"] is not None
    assert b"ACK" in r["ack"]


def test_handle_client_ml_kem_records_vote():
    """handle_client must increment the tally for the cast vote."""
    _simulate_client_server_exchange("ml_kem", "Alice")
    assert server_module._tally["Alice"] == 1


def test_handle_client_hybrid_sends_ack():
    r = _simulate_client_server_exchange("hybrid", "Bob")
    assert r["server_error"] is None
    assert r["client_error"] is None
    assert r["ack"] is not None
    assert b"ACK" in r["ack"]


def test_handle_client_hybrid_records_vote():
    _simulate_client_server_exchange("hybrid", "Charlie")
    assert server_module._tally["Charlie"] == 1


def test_handle_client_multiple_votes_accumulate():
    """Simulate two separate connections and confirm both votes are counted."""
    _simulate_client_server_exchange("ml_kem", "Alice")
    _simulate_client_server_exchange("ml_kem", "Bob")
    assert server_module._tally["Alice"] == 1
    assert server_module._tally["Bob"] == 1


# ---------------------------------------------------------------------------
# handle_client — mode mismatch
# ---------------------------------------------------------------------------

def test_handle_client_mode_mismatch_does_not_crash():
    """
    When the client announces a different mode than the server expects,
    handle_client must not raise an exception — it sends an error message
    and closes the connection gracefully.
    """
    r = _simulate_client_server_exchange("ml_kem", "Alice", server_mode="hybrid")
    assert r["server_error"] is None
    # No vote should have been recorded.
    assert sum(server_module._tally.values()) == 0
