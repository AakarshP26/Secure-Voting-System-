"""
kdf.py — Key Derivation from raw shared secrets to AES-256 keys.

WHY THIS EXISTS
Each of our key-exchange methods produces a "shared secret" of a
different size and structure:
  - Classical DH (2048-bit): ~256 raw bytes, lots of structure
  - ML-KEM-768:               32 bytes, already uniformly random
  - Hybrid:                   32 bytes, output of internal HKDF

You should NEVER use a raw shared secret directly as an AES key:
  - DH output has bias (numbers near 0 or near p are less common).
  - Different KEX modes produce different lengths, so the rest of the
    code would need three different paths.

SOLUTION: a single KDF (Key Derivation Function) that takes any-shape
shared secret and outputs a clean uniform 32-byte AES key.

We use HKDF-SHA256 with a domain-separation `info` string so that
different protocols using the same shared secret derive different keys.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Length of the derived key — 32 bytes = 256 bits = AES-256.
AES_KEY_LENGTH = 32


def derive_aes_key(shared_secret: bytes, info: bytes = b"voting-system aes key") -> bytes:
    """
    Derive a 32-byte AES-256 key from a raw shared secret using HKDF-SHA256.

    Args:
        shared_secret: Output of any of our KEX modes.
        info:          Domain-separation string. Same value on both sides.

    Returns:
        32 bytes suitable for use as an AES-256-GCM key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=b"",          # Empty salt — we have no shared random salt available.
        info=info,         # Domain separation.
    )
    return hkdf.derive(shared_secret)