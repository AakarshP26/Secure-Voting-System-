"""
server.py — Secure Chat Server (backend)

Pivoted from: Secure Voting System
Now: Secure Chat Server with pluggable post-quantum key exchange.

Usage:
    python backend/server.py --mode dh
    python backend/server.py --mode ml_kem
    python backend/server.py --mode hybrid
    python backend/server.py --mode dh --cache-params

Architecture:
    1. Listen on TCP port.
    2. For each new connection (in its own thread):
       a. Read 1-byte mode marker (validated against server config)
       b. Run pluggable key exchange handler → raw shared secret
       c. Derive AES-256 key via HKDF-SHA256 ("secure-chat aes key")
       d. Receive AES-GCM-encrypted JSON message, decrypt, process
       e. Send encrypted JSON ACK back

Author: Aakarsh Prabhu
"""

import argparse
import socket
import sys
import threading
import json

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.kex_handlers import get_handler
from crypto.kdf import derive_aes_key
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from utils.protocol import send_msg, recv_msg


HOST = "127.0.0.1"
PORT = 65432


# ---------------------------------------------------------------------
# In-memory message log (Phase 1: will move to SQLite in Phase 2)
# ---------------------------------------------------------------------
_log_lock = threading.Lock()
_message_log: list[dict] = []


def _record_message(payload: dict) -> None:
    with _log_lock:
        _message_log.append(payload)


def _print_log() -> None:
    with _log_lock:
        if not _message_log:
            print("[LOG] (no messages yet)")
            return
        print("[LOG]")
        for msg in _message_log:
            sender = msg.get("from", "unknown")
            data = msg.get("data", "")
            print(f"   {sender}: {data}")


# ---------------------------------------------------------------------
# Per-client handler (runs in its own thread)
# ---------------------------------------------------------------------

def handle_client(conn: socket.socket, addr: tuple, mode: str,
                  cached_dh_params=None) -> None:
    print(f"[+] New connection from {addr} (mode={mode})")
    try:
        # 1. Read mode marker from client and validate.
        client_mode_byte = recv_msg(conn).decode("utf-8")
        if client_mode_byte != mode:
            print(f"[!] Mode mismatch: server={mode!r}, client={client_mode_byte!r}")
            send_msg(conn, b"ERR: mode mismatch")
            return

        # 2. Run the key exchange.
        handler = get_handler(mode)
        if mode == "dh" and cached_dh_params is not None:
            handler.cached_params = cached_dh_params
        shared_secret = handler.server_side(conn)
        print(f"[OK] {addr} key exchange complete ({len(shared_secret)} bytes raw secret)")

        # 3. Derive AES key.
        aes_key = derive_aes_key(shared_secret)

        # 4. Receive encrypted JSON payload, decrypt, parse, record.
        encrypted_payload = recv_msg(conn)
        plaintext = aes_decrypt(aes_key, encrypted_payload)
        payload = json.loads(plaintext.decode("utf-8"))
        print(f"[MSG] from {addr}: {payload}")
        _record_message(payload)

        # 5. Send encrypted JSON ACK.
        ack = {
            "type": "ack",
            "status": "delivered",
            "message_id": payload.get("message_id", ""),
        }
        ack_blob = aes_encrypt(aes_key, json.dumps(ack).encode("utf-8"))
        send_msg(conn, ack_blob)

        # 6. Print updated log.
        _print_log()

    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON from {addr}: {e}")
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

def start_server(mode: str, cache_params: bool = False) -> None:
    cached_dh_params = None
    if mode == "dh" and cache_params:
        from crypto.dh import generate_parameters as dh_generate_parameters
        print("[SERVER] Pre-generating DH parameters (this may take ~30s)...")
        cached_dh_params = dh_generate_parameters(key_size=2048)
        print("[SERVER] DH parameters ready.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        cache_note = " (DH params cached)" if cached_dh_params else ""
        print(f"[SERVER] Listening on {HOST}:{PORT} (mode={mode}){cache_note}")

        while True:
            conn, addr = s.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, mode, cached_dh_params),
                daemon=True,
            )
            t.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure chat server")
    parser.add_argument(
        "--mode",
        choices=["dh", "ml_kem", "hybrid"],
        required=True,
        help="Key exchange mode",
    )
    parser.add_argument(
        "--cache-params",
        action="store_true",
        help="Generate DH parameters once at startup and reuse them (DH only)",
    )
    args = parser.parse_args()

    try:
        start_server(args.mode, cache_params=args.cache_params)
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down (Ctrl+C pressed)")
        _print_log()


if __name__ == "__main__":
    main()