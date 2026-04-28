"""
kex_handlers.py — Pluggable key exchange handlers.

Each handler implements server_side(conn) and client_side(conn)
to allow the rest of the system to be mode-agnostic.

DHHandler can optionally use cached parameters set on the instance
via .cached_params, otherwise generates fresh parameters per call.
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


class KexHandler(ABC):
    """Abstract base class for key exchange handlers."""

    @abstractmethod
    def server_side(self, conn: socket.socket) -> bytes: ...

    @abstractmethod
    def client_side(self, conn: socket.socket) -> bytes: ...


class DHHandler(KexHandler):
    """Classical 2048-bit Diffie-Hellman."""

    def server_side(self, conn: socket.socket) -> bytes:
        from cryptography.hazmat.primitives import serialization

        # Reuse cached parameters if the server pre-generated them at startup,
        # else generate fresh (the slow path — measures worst-case DH cost).
        parameters = getattr(self, "cached_params", None)
        if parameters is None:
            parameters = dh_generate_parameters(key_size=2048)

        server_priv, server_pub = dh_generate_keypair(parameters)

        params_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3,
        )
        pubkey_bytes = dh_serialize_public_key(server_pub)
        send_msg(conn, params_bytes)
        send_msg(conn, pubkey_bytes)

        client_pub_bytes = recv_msg(conn)
        client_pub = dh_deserialize_public_key(client_pub_bytes)

        return dh_derive_shared_secret(server_priv, client_pub)

    def client_side(self, conn: socket.socket) -> bytes:
        from cryptography.hazmat.primitives import serialization

        params_bytes = recv_msg(conn)
        server_pub_bytes = recv_msg(conn)

        parameters = serialization.load_pem_parameters(params_bytes)
        server_pub = dh_deserialize_public_key(server_pub_bytes)

        client_priv, client_pub = dh_generate_keypair(parameters)

        send_msg(conn, dh_serialize_public_key(client_pub))

        return dh_derive_shared_secret(client_priv, server_pub)


class MLKEMHandler(KexHandler):
    """Pure post-quantum ML-KEM-768."""

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


class HybridHandler(KexHandler):
    """Hybrid X25519 + ML-KEM-768."""

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


_HANDLERS = {
    "dh": DHHandler,
    "ml_kem": MLKEMHandler,
    "hybrid": HybridHandler,
}


def get_handler(mode: str) -> KexHandler:
    mode = mode.lower()
    if mode not in _HANDLERS:
        raise ValueError(
            f"Unknown mode '{mode}'. Choose from: {list(_HANDLERS.keys())}"
        )
    return _HANDLERS[mode]()