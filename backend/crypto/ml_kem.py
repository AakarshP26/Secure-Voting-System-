"""
ml_kem.py — Post-Quantum Key Encapsulation Mechanism (ML-KEM-768)

ML-KEM (Module-Lattice KEM) is the NIST-standardized post-quantum
key exchange algorithm, formerly known as Kyber. Standardized as
FIPS 203 in August 2024.

Why ML-KEM instead of Diffie-Hellman?
  - DH security relies on the discrete logarithm problem.
  - A sufficiently large quantum computer can solve discrete log
    in polynomial time using Shor's algorithm.
  - ML-KEM is based on the Module Learning With Errors (MLWE) problem
    over polynomial rings, which is believed to be quantum-resistant.

KEM vs DH — protocol difference:
  - DH: both sides do exponentiation, both contribute to the secret.
  - KEM: server publishes a public key. Client "encapsulates" a
    random secret using that public key, sending back a ciphertext.
    Server "decapsulates" the ciphertext using its private key
    to recover the same secret.

We use ML-KEM-768 (security ~AES-192).

Author: Aakarsh Prabhu
"""

from pqcrypto.kem.ml_kem_768 import (
    generate_keypair as _kem_generate_keypair,
    encrypt as _kem_encapsulate,
    decrypt as _kem_decapsulate,
)


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a fresh ML-KEM-768 keypair on the SERVER side.

    Returns:
        Tuple (public_key, secret_key) as raw bytes.
    """
    public_key, secret_key = _kem_generate_keypair()
    return public_key, secret_key


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Client-side: given the server's public key, generate a fresh shared
    secret and the ciphertext that lets the server recover it.

    Returns:
        Tuple (ciphertext, shared_secret).
    """
    ciphertext, shared_secret = _kem_encapsulate(public_key)
    return ciphertext, shared_secret


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Server-side: given my secret key and the client's ciphertext,
    recover the same shared secret the client computed.

    Returns:
        32-byte shared secret, identical to client's.
    """
    return _kem_decapsulate(secret_key, ciphertext)