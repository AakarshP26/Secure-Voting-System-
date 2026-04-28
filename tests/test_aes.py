"""
test_aes.py — Unit tests for the AES-256-GCM module.

Run with:
    pytest tests/test_aes.py -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from cryptography.exceptions import InvalidTag
from crypto.aes import encrypt, decrypt, KEY_SIZE_BYTES, NONCE_SIZE_BYTES


def _fresh_key() -> bytes:
    """Helper: generate a random 32-byte key for tests."""
    return os.urandom(KEY_SIZE_BYTES)


def test_encrypt_decrypt_roundtrip():
    """The whole point: decrypt(encrypt(x)) == x."""
    key = _fresh_key()
    plaintext = b"Vote: Alice"

    blob = encrypt(key, plaintext)
    recovered = decrypt(key, blob)

    assert recovered == plaintext


def test_two_encryptions_of_same_message_differ():
    """
    Random nonce means two encryptions of identical plaintext must
    produce different ciphertexts. Otherwise an observer could infer
    repeated votes.
    """
    key = _fresh_key()
    plaintext = b"Vote: Bob"

    blob1 = encrypt(key, plaintext)
    blob2 = encrypt(key, plaintext)

    assert blob1 != blob2


def test_decrypt_with_wrong_key_fails():
    """Wrong key must NOT decrypt — must raise InvalidTag."""
    key1 = _fresh_key()
    key2 = _fresh_key()
    blob = encrypt(key1, b"secret vote")

    with pytest.raises(InvalidTag):
        decrypt(key2, blob)


def test_tampered_ciphertext_is_rejected():
    """
    Flipping a single bit in the ciphertext must cause GCM to reject it.
    This is the core integrity guarantee.
    """
    key = _fresh_key()
    blob = bytearray(encrypt(key, b"hello"))

    # Flip a bit somewhere in the middle (not in nonce, to be sure).
    blob[len(blob) // 2] ^= 0x01

    with pytest.raises(InvalidTag):
        decrypt(key, bytes(blob))


def test_associated_data_must_match():
    """If AAD differs at decrypt time, decryption must fail."""
    key = _fresh_key()
    plaintext = b"vote"
    aad = b"voter-id-42"

    blob = encrypt(key, plaintext, associated_data=aad)

    # Same AAD → fine
    assert decrypt(key, blob, associated_data=aad) == plaintext

    # Different AAD → must fail
    with pytest.raises(InvalidTag):
        decrypt(key, blob, associated_data=b"voter-id-99")


def test_invalid_key_size_raises():
    """Keys of wrong length must fail loudly, not silently truncate/pad."""
    bad_key = os.urandom(16)  # 128-bit key, not 256

    with pytest.raises(ValueError):
        encrypt(bad_key, b"x")

    with pytest.raises(ValueError):
        decrypt(bad_key, b"x" * 50)


def test_blob_structure():
    """Output blob starts with the 12-byte nonce."""
    key = _fresh_key()
    plaintext = b"hello world"
    blob = encrypt(key, plaintext)

    # Blob length: 12 (nonce) + len(plaintext) + 16 (tag)
    assert len(blob) == NONCE_SIZE_BYTES + len(plaintext) + 16