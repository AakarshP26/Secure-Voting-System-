"""
server.py — Secure voting server with pluggable key exchange.

Usage:
    python3.12 src/server.py --mode dh
    python3.12 src/server.py --mode ml_kem
    python3.12 src/server.py --mode hybrid

Architecture:
    1. Listen on TCP port.
    2. For each new connection (in its own thread):
       a. Read 1-byte mode marker (validated against server config)
       b. Run pluggable key exchange handler → raw shared secret
       c. Derive AES-256 key via HKDF-SHA256
       d. Receive AES-GCM-encrypted vote, decrypt, tally
       e. Send encrypted ACK back

Author: Aakarsh Prabhu
"""

import argparse
import socket
import sys
import threading
from collections import Counter

# Allow `from crypto...` and `from utils...` imports
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.kex_handlers import get_handler
from crypto.kdf import derive_aes_key
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from utils.protocol import send_msg, recv_msg


HOST = "127.0.0.1"
PORT = 65432


# ---------------------------------------------------------------------
# Vote tally — shared across threads, protected by a lock
# ---------------------------------------------------------------------
_tally_lock = threading.Lock()
_tally: Counter = Counter()


def _record_vote(candidate: str) -> None:
    with _tally_lock:
        _tally[candidate] += 1


def _print_tally() -> None:
    with _tally_lock:
        if not _tally:
            print("[TALLY] (no votes yet)")
            return
        print("[TALLY]")
        for cand, count in _tally.most_common():
            print(f"   {cand}: {count}")


# ---------------------------------------------------------------------
# Per-client handler (runs in its own thread)
# ---------------------------------------------------------------------

def handle_client(conn: socket.socket, addr: tuple, mode: str) -> None:
    print(f"[+] New connection from {addr} (mode={mode})")
    try:
        # 1. Read 1-byte mode marker from client and validate.
        client_mode_byte = recv_msg(conn).decode("utf-8")
        if client_mode_byte != mode:
            print(f"[!] Mode mismatch: server={mode!r}, client={client_mode_byte!r}")
            send_msg(conn, b"ERR: mode mismatch")
            return

        # 2. Run the key exchange.
        handler = get_handler(mode)
        shared_secret = handler.server_side(conn)
        print(f"[OK] {addr} key exchange complete ({len(shared_secret)} bytes raw secret)")

        # 3. Derive AES key.
        aes_key = derive_aes_key(shared_secret)

        # 4. Receive encrypted vote, decrypt, record.
        encrypted_vote = recv_msg(conn)
        plaintext = aes_decrypt(aes_key, encrypted_vote)
        vote = plaintext.decode("utf-8").strip()
        print(f"[VOTE] from {addr}: {vote!r}")
        _record_vote(vote)

        # 5. Send encrypted ACK.
        ack_blob = aes_encrypt(aes_key, b"ACK: vote received")
        send_msg(conn, ack_blob)

        # 6. Print updated tally.
        _print_tally()

    except ConnectionError as e:
        print(f"[-] {addr} disconnected: {e}")
    except Exception as e:
        print(f"[!] Error handling {addr}: {type(e).__name__}: {e}")
    finally:
        conn.close()
        print(f"[-] Connection closed with {addr}")


# ---------------------------------------------------------------------
# Server main loop
# ---------------------------------------------------------------------

def start_server(mode: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[SERVER] Listening on {HOST}:{PORT} (mode={mode})")

        while True:
            conn, addr = s.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, mode),
                daemon=True,
            )
            t.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure voting server")
    parser.add_argument(
        "--mode",
        choices=["dh", "ml_kem", "hybrid"],
        required=True,
        help="Key exchange mode",
    )
    args = parser.parse_args()

    try:
        start_server(args.mode)
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down (Ctrl+C pressed)")
        _print_tally()


if __name__ == "__main__":
    main()