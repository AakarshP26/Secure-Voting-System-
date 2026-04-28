"""
test_ml_kem.py — Unit tests for the ML-KEM-768 module.

Run with:
    pytest tests/test_ml_kem.py -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto.ml_kem import generate_keypair, encapsulate, decapsulate


def test_encapsulate_decapsulate_roundtrip():
    """The whole point: client and server must derive the same secret."""
    pk, sk = generate_keypair()
    ciphertext, client_secret = encapsulate(pk)
    server_secret = decapsulate(sk, ciphertext)

    assert client_secret == server_secret


def test_shared_secret_is_32_bytes():
    """ML-KEM-768 always produces a 32-byte (256-bit) shared secret."""
    pk, sk = generate_keypair()
    _, secret = encapsulate(pk)

    assert isinstance(secret, bytes)
    assert len(secret) == 32


def test_different_sessions_produce_different_secrets():
    """Each encapsulation must yield a fresh, independent secret."""
    pk, _ = generate_keypair()
    _, secret1 = encapsulate(pk)
    _, secret2 = encapsulate(pk)

    assert secret1 != secret2


def test_public_and_secret_keys_have_expected_sizes():
    """Sanity: ML-KEM-768 spec sizes (pk=1184 bytes, sk=2400 bytes)."""
    pk, sk = generate_keypair()
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_ciphertext_has_expected_size():
    """ML-KEM-768 ciphertext is always 1088 bytes."""
    pk, _ = generate_keypair()
    ciphertext, _ = encapsulate(pk)

    assert len(ciphertext) == 1088


def test_decapsulate_with_wrong_secret_key_returns_different_secret():
    """
    Decapsulating a ciphertext with a different (incorrect) secret key must
    not recover the original shared secret.  ML-KEM has implicit rejection:
    instead of raising an exception it returns a pseudorandom decoy value.
    """
    pk, _ = generate_keypair()
    _, wrong_sk = generate_keypair()  # fresh unrelated keypair

    ciphertext, client_secret = encapsulate(pk)
    wrong_secret = decapsulate(wrong_sk, ciphertext)

    assert wrong_secret != client_secret


def test_generate_keypair_returns_distinct_keys_each_call():
    """Every generate_keypair call must yield a fresh, independent keypair."""
    pk1, sk1 = generate_keypair()
    pk2, sk2 = generate_keypair()
    assert pk1 != pk2
    assert sk1 != sk2