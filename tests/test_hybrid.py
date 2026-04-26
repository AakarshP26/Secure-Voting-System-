"""
test_hybrid.py — Unit tests for the hybrid (X25519 + ML-KEM-768) module.

Run with:
    pytest tests/test_hybrid.py -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto.hybrid import (
    server_generate_keys,
    client_handshake,
    server_finalize,
    _combine_secrets,
)


def test_hybrid_handshake_produces_matching_secrets():
    """The full hybrid handshake: client and server must derive the same key."""
    server_keys = server_generate_keys()

    client_response = client_handshake(
        ml_kem_pk=server_keys["ml_kem_pk"],
        server_x25519_pub=server_keys["x25519_pub"],
    )

    server_secret = server_finalize(
        server_keys=server_keys,
        ml_kem_ciphertext=client_response["ml_kem_ciphertext"],
        client_x25519_pub=client_response["x25519_pub"],
    )

    assert client_response["shared_secret"] == server_secret


def test_hybrid_secret_is_32_bytes():
    """Hybrid output is always a clean 32-byte (256-bit) key from HKDF."""
    server_keys = server_generate_keys()
    client_response = client_handshake(
        ml_kem_pk=server_keys["ml_kem_pk"],
        server_x25519_pub=server_keys["x25519_pub"],
    )
    assert len(client_response["shared_secret"]) == 32


def test_two_independent_hybrid_sessions_differ():
    """Two fresh sessions must produce different shared secrets."""
    sk1 = server_generate_keys()
    sk2 = server_generate_keys()

    c1 = client_handshake(sk1["ml_kem_pk"], sk1["x25519_pub"])
    c2 = client_handshake(sk2["ml_kem_pk"], sk2["x25519_pub"])

    assert c1["shared_secret"] != c2["shared_secret"]


def test_combiner_changes_when_either_input_changes():
    """
    Critical security property: HKDF combiner output must change if EITHER
    input changes. Otherwise an attacker who breaks one half could substitute.
    """
    base = _combine_secrets(b"A" * 32, b"B" * 32)
    diff_kem = _combine_secrets(b"X" * 32, b"B" * 32)
    diff_x25519 = _combine_secrets(b"A" * 32, b"Y" * 32)

    assert base != diff_kem
    assert base != diff_x25519
    assert diff_kem != diff_x25519


def test_hybrid_is_deterministic_given_same_inputs():
    """The combiner is a pure function: same inputs → same output."""
    s1 = _combine_secrets(b"A" * 32, b"B" * 32)
    s2 = _combine_secrets(b"A" * 32, b"B" * 32)
    assert s1 == s2