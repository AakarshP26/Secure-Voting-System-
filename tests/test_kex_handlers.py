"""
test_kex_handlers.py — Unit tests for the pluggable key exchange handlers.

Covers: DHHandler, MLKEMHandler, HybridHandler, and get_handler() in
crypto/kex_handlers.py.

Each handler test spins up server_side and client_side in separate threads
connected by an in-process socket pair, mirrors the real client–server
interaction without touching the network.

Run with:
    pytest tests/test_kex_handlers.py -v
"""

import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto.kex_handlers import (
    DHHandler,
    HybridHandler,
    KexHandler,
    MLKEMHandler,
    get_handler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_handler_pair(server_handler, client_handler, timeout=10):
    """
    Run server_handler.server_side and client_handler.client_side concurrently
    over an in-process socket pair.

    Returns (server_secret, client_secret) on success.
    Raises AssertionError if either side raises an exception.

    Parameters
    ----------
    server_handler : KexHandler
        Handler whose server_side will be called.
    client_handler : KexHandler
        Handler whose client_side will be called.
    timeout : float
        Seconds to wait for each thread to complete (default: 10).
    """
    server_sock, client_sock = socket.socketpair()
    results = {}
    errors = {}

    def _server():
        try:
            results["server"] = server_handler.server_side(server_sock)
        except Exception as exc:
            errors["server"] = exc
        finally:
            server_sock.close()

    def _client():
        try:
            results["client"] = client_handler.client_side(client_sock)
        except Exception as exc:
            errors["client"] = exc
        finally:
            client_sock.close()

    t_s = threading.Thread(target=_server, daemon=True)
    t_c = threading.Thread(target=_client, daemon=True)
    t_s.start()
    t_c.start()
    t_s.join(timeout=timeout)
    t_c.join(timeout=timeout)

    if errors:
        raise AssertionError(f"Handler thread errors: {errors}")
    assert "server" in results and "client" in results, "Threads did not complete"
    return results["server"], results["client"]


# ---------------------------------------------------------------------------
# Shared DH parameters — generated once at module level so every DH test
# reuses them and avoids the expensive (~30 s) parameter-generation step.
# ---------------------------------------------------------------------------

_DH_PARAMS = None


def _get_dh_params():
    global _DH_PARAMS
    if _DH_PARAMS is None:
        from crypto.dh import generate_parameters
        _DH_PARAMS = generate_parameters(key_size=2048)
    return _DH_PARAMS


# ---------------------------------------------------------------------------
# get_handler — factory function
# ---------------------------------------------------------------------------

def test_get_handler_dh_returns_dh_handler():
    assert isinstance(get_handler("dh"), DHHandler)


def test_get_handler_ml_kem_returns_ml_kem_handler():
    assert isinstance(get_handler("ml_kem"), MLKEMHandler)


def test_get_handler_hybrid_returns_hybrid_handler():
    assert isinstance(get_handler("hybrid"), HybridHandler)


def test_get_handler_is_case_insensitive():
    """Mode strings are lowercased before lookup."""
    assert isinstance(get_handler("DH"), DHHandler)
    assert isinstance(get_handler("ML_KEM"), MLKEMHandler)
    assert isinstance(get_handler("HYBRID"), HybridHandler)


def test_get_handler_unknown_mode_raises_value_error():
    with pytest.raises(ValueError, match="Unknown mode"):
        get_handler("rsa")


def test_get_handler_empty_string_raises_value_error():
    with pytest.raises(ValueError):
        get_handler("")


def test_get_handler_returns_fresh_instance_each_call():
    """Each call returns a new handler object, not a cached singleton."""
    h1 = get_handler("ml_kem")
    h2 = get_handler("ml_kem")
    assert h1 is not h2


def test_all_handlers_are_kex_handler_subclasses():
    for mode in ("dh", "ml_kem", "hybrid"):
        assert isinstance(get_handler(mode), KexHandler)


# ---------------------------------------------------------------------------
# ML-KEM handler
# ---------------------------------------------------------------------------

def test_ml_kem_handler_both_sides_derive_same_secret():
    server_secret, client_secret = _run_handler_pair(MLKEMHandler(), MLKEMHandler())
    assert server_secret == client_secret


def test_ml_kem_handler_secret_is_32_bytes():
    server_secret, client_secret = _run_handler_pair(MLKEMHandler(), MLKEMHandler())
    assert len(server_secret) == 32
    assert len(client_secret) == 32


def test_ml_kem_handler_secret_is_bytes():
    server_secret, _ = _run_handler_pair(MLKEMHandler(), MLKEMHandler())
    assert isinstance(server_secret, bytes)


def test_ml_kem_handler_independent_sessions_differ():
    """Two separate ML-KEM handshakes must produce different shared secrets."""
    s1, _ = _run_handler_pair(MLKEMHandler(), MLKEMHandler())
    s2, _ = _run_handler_pair(MLKEMHandler(), MLKEMHandler())
    assert s1 != s2


# ---------------------------------------------------------------------------
# Hybrid handler
# ---------------------------------------------------------------------------

def test_hybrid_handler_both_sides_derive_same_secret():
    server_secret, client_secret = _run_handler_pair(HybridHandler(), HybridHandler())
    assert server_secret == client_secret


def test_hybrid_handler_secret_is_32_bytes():
    server_secret, client_secret = _run_handler_pair(HybridHandler(), HybridHandler())
    assert len(server_secret) == 32
    assert len(client_secret) == 32


def test_hybrid_handler_secret_is_bytes():
    server_secret, _ = _run_handler_pair(HybridHandler(), HybridHandler())
    assert isinstance(server_secret, bytes)


def test_hybrid_handler_independent_sessions_differ():
    s1, _ = _run_handler_pair(HybridHandler(), HybridHandler())
    s2, _ = _run_handler_pair(HybridHandler(), HybridHandler())
    assert s1 != s2


# ---------------------------------------------------------------------------
# DH handler (uses pre-generated params to keep the test fast)
# ---------------------------------------------------------------------------

def test_dh_handler_both_sides_derive_same_secret():
    """DH handshake: server and client must arrive at the same shared secret."""
    params = _get_dh_params()
    server_handler = DHHandler()
    server_handler.cached_params = params  # avoid re-generating parameters
    client_handler = DHHandler()

    server_secret, client_secret = _run_handler_pair(
        server_handler, client_handler, timeout=30
    )
    assert server_secret == client_secret


def test_dh_handler_secret_is_bytes_with_reasonable_length():
    params = _get_dh_params()
    server_handler = DHHandler()
    server_handler.cached_params = params
    client_handler = DHHandler()

    server_secret, _ = _run_handler_pair(server_handler, client_handler, timeout=30)
    assert isinstance(server_secret, bytes)
    # 2048-bit DH output: either 255 or 256 bytes depending on leading zeros.
    assert len(server_secret) in (255, 256)


def test_dh_handler_independent_sessions_differ():
    params = _get_dh_params()

    sh1 = DHHandler()
    sh1.cached_params = params
    s1, _ = _run_handler_pair(sh1, DHHandler(), timeout=30)

    sh2 = DHHandler()
    sh2.cached_params = params
    s2, _ = _run_handler_pair(sh2, DHHandler(), timeout=30)

    assert s1 != s2
