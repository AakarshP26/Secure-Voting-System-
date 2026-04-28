"""
client.py — Secure Chat Client (backend)

Pivoted from: Secure Voting System
Now: Sends a structured JSON chat message over a post-quantum secure channel.

Usage:
    python backend/client.py --mode dh --message "Hello"
    python backend/client.py --mode ml_kem --message "Hello" --quiet
    python backend/client.py --mode hybrid --message "Hello" --from alice

--message MSG   The chat message to send.
--from    NAME  Sender display name (default: "user").
--quiet         Suppress human-friendly logs; print one CSV-style metrics line.

Author: Aakarsh Prabhu
"""

import argparse
import socket
import sys
import os
import time
import json
import secrets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.kex_handlers import get_handler
from crypto.kdf import derive_aes_key
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from utils.protocol import send_msg, recv_msg


HOST = "127.0.0.1"
PORT = 65432


def get_message_from_user() -> str:
    """Interactive message prompt."""
    return input("Enter your message: ").strip()


def send_message(mode: str, sender: str, message: str, quiet: bool = False) -> dict:
    """
    Run the full secure message flow. Returns timing/byte metrics dict.

    Metrics returned:
        connect_ms        - TCP connect time
        handshake_ms      - key exchange time
        encrypt_send_ms   - time from encrypting to sending
        ack_ms            - waiting for + decrypting the ack
        total_ms          - end-to-end
        bytes_sent_app    - approximate bytes the client transmitted
        bytes_received_app - approximate bytes the client received
    """
    bytes_sent = 0
    bytes_received = 0

    def log(msg: str) -> None:
        if not quiet:
            print(msg)

    t0 = time.perf_counter_ns()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        log(f"[CLIENT] Connecting to {HOST}:{PORT} (mode={mode})...")
        s.connect((HOST, PORT))
        t_connected = time.perf_counter_ns()

        # Send mode marker.
        mode_bytes = mode.encode("utf-8")
        send_msg(s, mode_bytes)
        bytes_sent += 4 + len(mode_bytes)

        # Run key exchange.
        handler = get_handler(mode)
        t_handshake_start = time.perf_counter_ns()
        shared_secret = handler.client_side(s)
        t_handshake_end = time.perf_counter_ns()
        log(f"[OK] Key exchange complete ({len(shared_secret)} bytes raw secret)")

        # Derive AES key.
        aes_key = derive_aes_key(shared_secret)

        # Build structured JSON payload.
        payload = {
            "message_id": secrets.token_hex(16),
            "timestamp": time.time(),
            "type": "chat",
            "from": sender,
            "to": "server",
            "data": message,
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        # Encrypt and send.
        ciphertext = aes_encrypt(aes_key, payload_bytes)
        t_encrypt_done = time.perf_counter_ns()
        send_msg(s, ciphertext)
        bytes_sent += 4 + len(ciphertext)
        t_send_done = time.perf_counter_ns()
        log(f"[CLIENT] Sent encrypted message ({len(ciphertext)} bytes payload)")

        # Receive and decrypt ACK.
        ack_blob = recv_msg(s)
        bytes_received += 4 + len(ack_blob)
        ack = json.loads(aes_decrypt(aes_key, ack_blob).decode("utf-8"))
        t_ack = time.perf_counter_ns()
        log(f"[CLIENT] Server ACK: status={ack.get('status')} id={ack.get('message_id')}")

    t_end = time.perf_counter_ns()

    metrics = {
        "mode": mode,
        "message_id": payload["message_id"],
        "connect_ms": (t_connected - t0) / 1e6,
        "handshake_ms": (t_handshake_end - t_handshake_start) / 1e6,
        "encrypt_send_ms": (t_send_done - t_handshake_end) / 1e6,
        "ack_ms": (t_ack - t_send_done) / 1e6,
        "total_ms": (t_end - t0) / 1e6,
        "bytes_sent_app": bytes_sent,
        "bytes_received_app": bytes_received,
    }
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure chat client")
    parser.add_argument(
        "--mode",
        choices=["dh", "ml_kem", "hybrid"],
        required=True,
        help="Key exchange mode",
    )
    parser.add_argument(
        "--message",
        help="Message to send (skips interactive prompt)",
    )
    parser.add_argument(
        "--from",
        dest="sender",
        default="user",
        help="Sender display name",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress logs; print one machine-readable metrics line",
    )
    args = parser.parse_args()

    try:
        message = args.message if args.message else get_message_from_user()
        metrics = send_message(args.mode, args.sender, message, quiet=args.quiet)

        if args.quiet:
            print(",".join(f"{k}={v}" for k, v in metrics.items()))
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to the server. Is it running?", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[CLIENT] Cancelled.")


if __name__ == "__main__":
    main()