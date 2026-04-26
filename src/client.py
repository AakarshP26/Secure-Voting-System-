"""
client.py — Secure voter client with pluggable key exchange.

Usage:
    python3.12 src/client.py --mode dh
    python3.12 src/client.py --mode ml_kem
    python3.12 src/client.py --mode hybrid

Flow:
    1. TCP connect to server.
    2. Send 1-byte mode marker so server can validate.
    3. Run client-side handshake → raw shared secret.
    4. Derive AES-256 key via HKDF-SHA256.
    5. Prompt voter, encrypt vote, send.
    6. Receive encrypted ACK, decrypt, display.

Author: Aakarsh Prabhu
"""

import argparse
import socket
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.kex_handlers import get_handler
from crypto.kdf import derive_aes_key
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from utils.protocol import send_msg, recv_msg


HOST = "127.0.0.1"
PORT = 65432


def get_vote_from_user() -> str:
    candidates = {"1": "Alice", "2": "Bob", "3": "Charlie"}
    print("\n=== BALLOT ===")
    for k, name in candidates.items():
        print(f"  [{k}] {name}")
    print("==============")
    while True:
        choice = input("Enter your vote (1/2/3): ").strip()
        if choice in candidates:
            return candidates[choice]
        print("Invalid choice, try again.")


def cast_vote(mode: str, vote: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[CLIENT] Connecting to {HOST}:{PORT} (mode={mode})...")
        s.connect((HOST, PORT))

        # Send mode marker so server can validate.
        send_msg(s, mode.encode("utf-8"))

        # Run handshake.
        handler = get_handler(mode)
        shared_secret = handler.client_side(s)
        print(f"[OK] Key exchange complete ({len(shared_secret)} bytes raw secret)")

        # Derive AES key.
        aes_key = derive_aes_key(shared_secret)

        # Encrypt + send vote.
        ciphertext = aes_encrypt(aes_key, vote.encode("utf-8"))
        send_msg(s, ciphertext)
        print(f"[CLIENT] Sent encrypted vote ({len(ciphertext)} bytes on wire)")

        # Receive + decrypt ACK.
        ack_blob = recv_msg(s)
        ack = aes_decrypt(aes_key, ack_blob).decode("utf-8")
        print(f"[CLIENT] Server response: {ack}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure voter client")
    parser.add_argument(
        "--mode",
        choices=["dh", "ml_kem", "hybrid"],
        required=True,
        help="Key exchange mode",
    )
    args = parser.parse_args()

    try:
        vote = get_vote_from_user()
        cast_vote(args.mode, vote)
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to the server. Is it running?")
    except KeyboardInterrupt:
        print("\n[CLIENT] Cancelled.")


if __name__ == "__main__":
    main()