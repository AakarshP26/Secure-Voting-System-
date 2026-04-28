"""
aes.py — AES-256-GCM Authenticated Encryption

This module wraps the `cryptography` library's AES-GCM primitive in a
small, ergonomic API tailored for the voting protocol.

WHY AES-256-GCM?
  - GCM is Authenticated Encryption with Associated Data (AEAD): it
    provides confidentiality AND integrity in a single operation.
  - Compare to AES-CBC, which gives only confidentiality and forces
    you to add a separate MAC (HMAC) — two pieces, more failure modes.
  - Used in TLS 1.3, SSH, IPsec — current industry standard.

WIRE FORMAT
  We bundle (nonce || ciphertext_with_tag) into a single bytes blob:
    [12 bytes nonce] [N bytes ciphertext] [16 bytes auth tag]

  The `cryptography` library appends the tag to the ciphertext for us,
  so we just store nonce explicitly and let GCM handle the rest.

CRITICAL: NONCE UNIQUENESS
  GCM's security catastrophically fails if a (key, nonce) pair is
  ever reused. We generate a fresh 96-bit random nonce on every call.
  Birthday-bound collision probability for 96-bit nonces is negligible
  for our scale (~2^32 messages before any worry).

Author: Aakarsh Prabhu
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# AES-256 means a 256-bit (32-byte) key.
KEY_SIZE_BYTES = 32

# GCM's recommended nonce length is 96 bits (12 bytes).
NONCE_SIZE_BYTES = 12


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Encrypt `plaintext` under AES-256-GCM with a fresh random nonce.

    Args:
        key:             32-byte AES key.
        plaintext:       The message to encrypt.
        associated_data: Optional public data that is authenticated but
                         NOT encrypted. (e.g. protocol version headers.)
                         Tampering with associated_data on decryption fails.

    Returns:
        Bytes blob:  [12-byte nonce] || [ciphertext] || [16-byte tag]
        Self-contained — the receiver needs only this and the key.

    Raises:
        ValueError if `key` is the wrong length.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(
            f"AES-256 key must be {KEY_SIZE_BYTES} bytes, got {len(key)}"
        )

    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext_with_tag


def decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt and verify a blob produced by `encrypt`.

    Args:
        key:             32-byte AES key (must match the encryption key).
        blob:            Output of encrypt() — nonce || ciphertext || tag.
        associated_data: Must match what was passed at encryption time.

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError if the key is the wrong length.
        cryptography.exceptions.InvalidTag if the blob has been tampered
            with, the key is wrong, or the associated_data doesn't match.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(
            f"AES-256 key must be {KEY_SIZE_BYTES} bytes, got {len(key)}"
        )
    if len(blob) < NONCE_SIZE_BYTES + 16:
        # Need at least nonce (12) + tag (16) = 28 bytes.
        raise ValueError("Blob is too short to be a valid GCM message")

    nonce = blob[:NONCE_SIZE_BYTES]
    ciphertext_with_tag = blob[NONCE_SIZE_BYTES:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)