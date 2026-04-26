"""
hybrid.py — Hybrid X25519 + ML-KEM-768 Key Exchange

This module implements the recommended post-quantum hybrid construction:
combine a classical KEX (X25519) and a post-quantum KEM (ML-KEM-768)
and derive a single shared secret from BOTH outputs.

Why hybrid?
  - Pure classical KEX is broken by future quantum computers.
  - Pure post-quantum KEM is mathematically newer and less battle-tested;
    a future cryptanalytic break would be catastrophic.
  - Hybrid is secure as long as AT LEAST ONE component is unbroken.
    This is what TLS, Signal, and SSH are deploying in 2024-2026.

Combiner construction (matches IETF hybrid TLS drafts):
    shared_secret = HKDF-SHA256(
        ikm  = ml_kem_secret || x25519_secret,
        salt = b"",
        info = b"tls13 hybrid",
        length = 32 bytes
    )

Author: Aakarsh Prabhu
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .ml_kem import (
    generate_keypair as kem_generate_keypair,
    encapsulate as kem_encapsulate,
    decapsulate as kem_decapsulate,
)


# ---------------------------------------------------------------------
# X25519 helpers
# ---------------------------------------------------------------------

def x25519_generate_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Generate an X25519 keypair. Returns (private_key, public_key_bytes)."""
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def x25519_derive_shared(
    private_key: X25519PrivateKey,
    peer_public_bytes: bytes,
) -> bytes:
    """Compute X25519 shared secret given my private key + peer's pubkey bytes."""
    peer_public = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public)


# ---------------------------------------------------------------------
# Combiner — HKDF over concatenated secrets
# ---------------------------------------------------------------------

def _combine_secrets(ml_kem_secret: bytes, x25519_secret: bytes) -> bytes:
    """
    Combine the two component shared secrets into one 32-byte session key
    using HKDF-SHA256. This is the standard hybrid combiner.
    """
    ikm = ml_kem_secret + x25519_secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"tls13 hybrid",
    )
    return hkdf.derive(ikm)


# ---------------------------------------------------------------------
# Server-side key generation
# ---------------------------------------------------------------------

def server_generate_keys() -> dict:
    """
    Server creates fresh ML-KEM and X25519 keypairs.

    Returns dict with:
        - 'ml_kem_pk':  public key bytes to send to client
        - 'ml_kem_sk':  private key bytes (kept by server)
        - 'x25519_priv': X25519 private key object (kept by server)
        - 'x25519_pub':  X25519 public key bytes to send to client
    """
    ml_kem_pk, ml_kem_sk = kem_generate_keypair()
    x25519_priv, x25519_pub = x25519_generate_keypair()

    return {
        "ml_kem_pk": ml_kem_pk,
        "ml_kem_sk": ml_kem_sk,
        "x25519_priv": x25519_priv,
        "x25519_pub": x25519_pub,
    }


# ---------------------------------------------------------------------
# Client-side
# ---------------------------------------------------------------------

def client_handshake(ml_kem_pk: bytes, server_x25519_pub: bytes) -> dict:
    """
    Client side: given the server's public keys, perform the hybrid handshake.

    Returns dict with:
        - 'ml_kem_ciphertext': KEM ciphertext to send to server
        - 'x25519_pub':        client's X25519 public key (to send to server)
        - 'shared_secret':     32-byte derived hybrid shared secret
    """
    kem_ct, kem_secret = kem_encapsulate(ml_kem_pk)

    client_x25519_priv, client_x25519_pub = x25519_generate_keypair()
    x25519_secret = x25519_derive_shared(client_x25519_priv, server_x25519_pub)

    shared = _combine_secrets(kem_secret, x25519_secret)

    return {
        "ml_kem_ciphertext": kem_ct,
        "x25519_pub": client_x25519_pub,
        "shared_secret": shared,
    }


# ---------------------------------------------------------------------
# Server-side finalization
# ---------------------------------------------------------------------

def server_finalize(
    server_keys: dict,
    ml_kem_ciphertext: bytes,
    client_x25519_pub: bytes,
) -> bytes:
    """
    Server side: given own keys + client's KEM ciphertext + client's X25519
    pubkey, derive the same hybrid shared secret the client computed.

    Returns:
        32-byte hybrid shared secret.
    """
    kem_secret = kem_decapsulate(server_keys["ml_kem_sk"], ml_kem_ciphertext)
    x25519_secret = x25519_derive_shared(
        server_keys["x25519_priv"], client_x25519_pub
    )
    return _combine_secrets(kem_secret, x25519_secret)