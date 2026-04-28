"""
dh.py — Classical Diffie-Hellman Key Exchange

This module implements the 1976 Diffie-Hellman key exchange protocol.
It is the BASELINE for our security analysis — secure against classical
computers, but theoretically breakable by a sufficiently large quantum
computer (the "harvest now, decrypt later" threat for long-lived secrets
like votes).

We use the well-vetted `cryptography` library rather than implementing
modular exponentiation ourselves. Reasons:
  - Naive implementations have timing side-channel vulnerabilities.
  - Vetted libraries handle parameter validation correctly.
  - "Don't roll your own crypto" is a foundational rule of the field.

Author: Aakarsh Prabhu
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------
# Parameter generation
# ---------------------------------------------------------------------

def generate_parameters(key_size: int = 2048) -> dh.DHParameters:
    """
    Generate fresh Diffie-Hellman parameters (p, g).

    Args:
        key_size: Bit length of the prime `p`. 2048 is the modern minimum.

    Returns:
        DHParameters object that both parties will use.
    """
    return dh.generate_parameters(generator=2, key_size=key_size)


# ---------------------------------------------------------------------
# Key pair generation
# ---------------------------------------------------------------------

def generate_keypair(parameters: dh.DHParameters):
    """
    Generate a (private_key, public_key) pair for one party.

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


# ---------------------------------------------------------------------
# Shared secret derivation
# ---------------------------------------------------------------------

def derive_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Compute the DH shared secret.

    Math: S = (peer_public_key) ^ (my_private_key) mod p
            = g ^ (a * b) mod p

    Both parties end up with IDENTICAL shared secrets.

    Returns:
        Shared secret as raw bytes (~256 bytes for 2048-bit DH).
    """
    return private_key.exchange(peer_public_key)


# ---------------------------------------------------------------------
# Serialization — convert keys to/from bytes for network transmission
# ---------------------------------------------------------------------

def serialize_public_key(public_key) -> bytes:
    """Serialize a DH public key to PEM-encoded bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(data: bytes):
    """Parse PEM-encoded public key bytes back into a usable key object."""
    return serialization.load_pem_public_key(data)
