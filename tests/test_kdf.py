"""
test_kdf.py — Unit tests for the KDF module.

Run with:
    pytest tests/test_kdf.py -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from crypto.kdf import derive_aes_key, AES_KEY_LENGTH


def test_output_is_correct_length():
    """Derived key is always exactly 32 bytes."""
    key = derive_aes_key(b"some shared secret material" * 4)
    assert len(key) == AES_KEY_LENGTH


def test_same_input_produces_same_output():
    """KDF is deterministic given the same inputs."""
    secret = b"X" * 64
    k1 = derive_aes_key(secret)
    k2 = derive_aes_key(secret)
    assert k1 == k2


def test_different_secrets_produce_different_keys():
    """Different shared secrets must produce different AES keys."""
    k1 = derive_aes_key(b"A" * 64)
    k2 = derive_aes_key(b"B" * 64)
    assert k1 != k2


def test_different_info_strings_produce_different_keys():
    """
    Domain separation: the same secret + different `info` must
    produce different keys. This is what protects against
    cross-protocol attacks.
    """
    secret = b"shared" * 10
    k1 = derive_aes_key(secret, info=b"protocol-A")
    k2 = derive_aes_key(secret, info=b"protocol-B")
    assert k1 != k2


def test_works_with_dh_sized_input():
    """Sanity: works on a ~256-byte DH-style secret without crashing."""
    secret = b"\xAB" * 256
    key = derive_aes_key(secret)
    assert len(key) == 32