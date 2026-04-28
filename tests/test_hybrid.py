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
    x25519_generate_keypair,
    x25519_derive_shared,
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


def test_x25519_keypair_pub_key_is_32_bytes():
    """X25519 raw public keys must be exactly 32 bytes."""
    _, pub_bytes = x25519_generate_keypair()
    assert isinstance(pub_bytes, bytes)
    assert len(pub_bytes) == 32


def test_x25519_two_keypairs_produce_same_shared_secret():
    """X25519 DH: both sides exchanging each other's public key must agree."""
    priv_a, pub_a = x25519_generate_keypair()
    priv_b, pub_b = x25519_generate_keypair()

    secret_ab = x25519_derive_shared(priv_a, pub_b)
    secret_ba = x25519_derive_shared(priv_b, pub_a)

    assert secret_ab == secret_ba
    assert len(secret_ab) == 32


def test_server_generate_keys_contains_expected_fields():
    """server_generate_keys must return all four expected key material fields."""
    keys = server_generate_keys()
    assert "ml_kem_pk" in keys
    assert "ml_kem_sk" in keys
    assert "x25519_priv" in keys
    assert "x25519_pub" in keys
    assert len(keys["x25519_pub"]) == 32