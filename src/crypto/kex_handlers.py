"""
kex_handlers.py — Pluggable key exchange handlers.

This module wraps each of our three key-exchange methods (DH, ML-KEM,
Hybrid) behind a uniform interface so the server/client code can be
mode-agnostic.

DESIGN PATTERN: Strategy.
The client and server each call:
    handler = get_handler(mode)
    shared_secret = handler.client_side(conn)   # or .server_side(conn)
…and the rest of their code is identical regardless of mode. This
makes Phase 5 benchmarking trivial: just loop over modes.

Each handler's responsibilities:
  - Implement server_side(conn) → bytes
  - Implement client_side(conn) → bytes
  - Send/receive whatever wire messages are needed (using protocol.py)
"""

from abc import ABC, abstractmethod
import socket

from utils.protocol import send_msg, recv_msg

from .dh import (
    generate_parameters as dh_generate_parameters,
    generate_keypair as dh_generate_keypair,
    derive_shared_secret as dh_derive_shared_secret,
    serialize_public_key as dh_serialize_public_key,
    deserialize_public_key as dh_deserialize_public_key,
)
from .ml_kem import (
    generate_keypair as kem_generate_keypair,
    encapsulate as kem_encapsulate,
    decapsulate as kem_decapsulate,
)
from .hybrid import (
    server_generate_keys as hybrid_server_generate_keys,
    client_handshake as hybrid_client_handshake,
    server_finalize as hybrid_server_finalize,
)


# ---------------------------------------------------------------------
# Abstract base class — defines the interface all handlers must implement
# ---------------------------------------------------------------------

class KexHandler(ABC):
    """Abstract base class for key exchange handlers."""

    @abstractmethod
    def server_side(self, conn: socket.socket) -> bytes:
        """Server-side handshake. Returns the raw shared secret (bytes)."""
        ...

    @abstractmethod
    def client_side(self, conn: socket.socket) -> bytes:
        """Client-side handshake. Returns the raw shared secret (bytes)."""
        ...


# ---------------------------------------------------------------------
# Classical Diffie-Hellman
# ---------------------------------------------------------------------

class DHHandler(KexHandler):
    """
    Classical 2048-bit Diffie-Hellman.

    Wire flow:
        Server → Client: DH parameters (PEM) + server pubkey (PEM)
        Client → Server: client pubkey (PEM)
    """

    def server_side(self, conn: socket.socket) -> bytes:
        # Generate fresh parameters and a keypair (slow ~30s for the params).
        parameters = dh_generate_parameters(key_size=2048)
        server_priv, server_pub = dh_generate_keypair(parameters)

        # Serialize parameters and pubkey, send to client.
        from cryptography.hazmat.primitives import serialization
        params_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3,
        )
        pubkey_bytes = dh_serialize_public_key(server_pub)
        send_msg(conn, params_bytes)
        send_msg(conn, pubkey_bytes)

        # Receive client's public key.
        client_pub_bytes = recv_msg(conn)
        client_pub = dh_deserialize_public_key(client_pub_bytes)

        # Derive shared secret.
        return dh_derive_shared_secret(server_priv, client_pub)

    def client_side(self, conn: socket.socket) -> bytes:
        from cryptography.hazmat.primitives import serialization

        # Receive parameters and server's pubkey.
        params_bytes = recv_msg(conn)
        server_pub_bytes = recv_msg(conn)

        parameters = serialization.load_pem_parameters(params_bytes)
        server_pub = dh_deserialize_public_key(server_pub_bytes)

        # Generate own keypair using same parameters.
        client_priv, client_pub = dh_generate_keypair(parameters)

        # Send our pubkey to server.
        send_msg(conn, dh_serialize_public_key(client_pub))

        # Derive shared secret.
        return dh_derive_shared_secret(client_priv, server_pub)


# ---------------------------------------------------------------------
# ML-KEM-768 (pure post-quantum)
# ---------------------------------------------------------------------

class MLKEMHandler(KexHandler):
    """
    Pure post-quantum ML-KEM-768.

    Wire flow:
        Server → Client: ML-KEM public key (1184 bytes)
        Client → Server: ML-KEM ciphertext (1088 bytes)
    """

    def server_side(self, conn: socket.socket) -> bytes:
        pk, sk = kem_generate_keypair()
        send_msg(conn, pk)
        ciphertext = recv_msg(conn)
        return kem_decapsulate(sk, ciphertext)

    def client_side(self, conn: socket.socket) -> bytes:
        pk = recv_msg(conn)
        ciphertext, shared_secret = kem_encapsulate(pk)
        send_msg(conn, ciphertext)
        return shared_secret


# ---------------------------------------------------------------------
# Hybrid X25519 + ML-KEM-768
# ---------------------------------------------------------------------

class HybridHandler(KexHandler):
    """
    Hybrid post-quantum + classical handshake.

    Wire flow:
        Server → Client: ML-KEM pubkey || X25519 pubkey
        Client → Server: ML-KEM ciphertext || client X25519 pubkey
    """

    def server_side(self, conn: socket.socket) -> bytes:
        keys = hybrid_server_generate_keys()
        send_msg(conn, keys["ml_kem_pk"])
        send_msg(conn, keys["x25519_pub"])

        ml_kem_ciphertext = recv_msg(conn)
        client_x25519_pub = recv_msg(conn)

        return hybrid_server_finalize(
            server_keys=keys,
            ml_kem_ciphertext=ml_kem_ciphertext,
            client_x25519_pub=client_x25519_pub,
        )

    def client_side(self, conn: socket.socket) -> bytes:
        ml_kem_pk = recv_msg(conn)
        server_x25519_pub = recv_msg(conn)

        response = hybrid_client_handshake(
            ml_kem_pk=ml_kem_pk,
            server_x25519_pub=server_x25519_pub,
        )
        send_msg(conn, response["ml_kem_ciphertext"])
        send_msg(conn, response["x25519_pub"])

        return response["shared_secret"]


# ---------------------------------------------------------------------
# Factory function — pick a handler by name
# ---------------------------------------------------------------------

_HANDLERS = {
    "dh": DHHandler,
    "ml_kem": MLKEMHandler,
    "hybrid": HybridHandler,
}


def get_handler(mode: str) -> KexHandler:
    """
    Return a handler instance for the given mode name.

    Args:
        mode: one of 'dh', 'ml_kem', 'hybrid'

    Raises:
        ValueError if mode is unrecognized.
    """
    mode = mode.lower()
    if mode not in _HANDLERS:
        raise ValueError(
            f"Unknown mode '{mode}'. Choose from: {list(_HANDLERS.keys())}"
        )
    return _HANDLERS[mode]()