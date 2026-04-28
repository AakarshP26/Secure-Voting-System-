

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from crypto.dh import (
    generate_parameters,
    generate_keypair,
    derive_shared_secret,
    serialize_public_key,
    deserialize_public_key,
)



PARAMETERS = generate_parameters(key_size=2048)


def test_shared_secret_matches_between_two_parties():
   
    alice_priv, alice_pub = generate_keypair(PARAMETERS)
    bob_priv, bob_pub = generate_keypair(PARAMETERS)

    alice_shared = derive_shared_secret(alice_priv, bob_pub)
    bob_shared = derive_shared_secret(bob_priv, alice_pub)

    assert alice_shared == bob_shared, "Shared secrets must match!"


def test_different_sessions_produce_different_secrets():
    
    a1_priv, _ = generate_keypair(PARAMETERS)
    _, b1_pub = generate_keypair(PARAMETERS)
    secret1 = derive_shared_secret(a1_priv, b1_pub)

    a2_priv, _ = generate_keypair(PARAMETERS)
    _, b2_pub = generate_keypair(PARAMETERS)
    secret2 = derive_shared_secret(a2_priv, b2_pub)

    assert secret1 != secret2


def test_public_key_serialization_roundtrip():
    
    alice_priv, alice_pub = generate_keypair(PARAMETERS)
    bob_priv, bob_pub = generate_keypair(PARAMETERS)

    bob_pub_bytes = serialize_public_key(bob_pub)
    bob_pub_restored = deserialize_public_key(bob_pub_bytes)

    alice_shared = derive_shared_secret(alice_priv, bob_pub_restored)
    bob_shared = derive_shared_secret(bob_priv, alice_pub)

    assert alice_shared == bob_shared


def test_serialized_public_key_is_pem_format():
   
    _, pub = generate_keypair(PARAMETERS)
    serialized = serialize_public_key(pub)

    assert b"BEGIN PUBLIC KEY" in serialized
    assert b"END PUBLIC KEY" in serialized


def test_shared_secret_is_bytes_with_expected_length():
   
    alice_priv, _ = generate_keypair(PARAMETERS)
    _, bob_pub = generate_keypair(PARAMETERS)

    secret = derive_shared_secret(alice_priv, bob_pub)

    assert isinstance(secret, bytes)
    assert len(secret) in (255, 256)