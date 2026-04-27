"""
client.py — Secure voter client with pluggable key exchange.

Usage:
    python3.12 src/client.py --mode dh
    python3.12 src/client.py --mode ml_kem --auto-vote Bob
    python3.12 src/client.py --mode hybrid --auto-vote Alice --quiet

--auto-vote VOTE   Skip the interactive ballot prompt; cast VOTE directly.
--quiet            Suppress human-friendly logs; print one CSV-style line
                   of metrics to stdout instead. Used by benchmark harness.

Author: Aakarsh Prabhu
"""

import argparse
import socket
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.kex_handlers import get_handler
from crypto.kdf import derive_aes_key
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from utils.protocol import send_msg, recv_msg


HOST = "127.0.0.1"
PORT = 65432

CANDIDATES = {"1": "Alice", "2": "Bob", "3": "Charlie"}


def get_vote_from_user() -> str:
    """Interactive ballot."""
    print("\n=== BALLOT ===")
    for k, name in CANDIDATES.items():
        print(f"  [{k}] {name}")
    print("==============")
    while True:
        choice = input("Enter your vote (1/2/3): ").strip()
        if choice in CANDIDATES:
            return CANDIDATES[choice]
        print("Invalid choice, try again.")


def cast_vote(mode: str, vote: str, quiet: bool = False) -> dict:
    """
    Run the full secure vote flow. Returns timing/byte metrics dict.

    Metrics returned:
        connect_ms        - TCP connect time
        handshake_ms      - key exchange time
        encrypt_send_ms   - time from encrypting vote to sending
        ack_ms            - waiting for + decrypting the ack
        total_ms          - end-to-end
        bytes_sent        - approximate bytes the client transmitted
        bytes_received    - approximate bytes the client received
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

        # Send mode marker
        mode_bytes = mode.encode("utf-8")
        send_msg(s, mode_bytes)
        bytes_sent += 4 + len(mode_bytes)  # 4-byte length prefix + payload

        # Run handshake — wrap a tiny tracking layer so we count bytes.
        # Easiest approach: capture totals after the fact via getsockopt-like
        # hack? Actually, simplest: just instrument by approximation.
        # The handler itself uses send_msg/recv_msg internally; we can't
        # intercept easily without rewriting. Instead, we'll only report
        # bytes at the application layer (mode marker, encrypted vote, ack).
        handler = get_handler(mode)
        t_handshake_start = time.perf_counter_ns()
        shared_secret = handler.client_side(s)
        t_handshake_end = time.perf_counter_ns()
        log(f"[OK] Key exchange complete ({len(shared_secret)} bytes raw secret)")

        # Derive AES key
        aes_key = derive_aes_key(shared_secret)

        # Encrypt + send vote
        ciphertext = aes_encrypt(aes_key, vote.encode("utf-8"))
        t_encrypt_done = time.perf_counter_ns()
        send_msg(s, ciphertext)
        bytes_sent += 4 + len(ciphertext)
        t_send_done = time.perf_counter_ns()
        log(f"[CLIENT] Sent encrypted vote ({len(ciphertext)} bytes payload)")

        # Receive ACK
        ack_blob = recv_msg(s)
        bytes_received += 4 + len(ack_blob)
        ack = aes_decrypt(aes_key, ack_blob).decode("utf-8")
        t_ack = time.perf_counter_ns()
        log(f"[CLIENT] Server response: {ack}")

    t_end = time.perf_counter_ns()

    metrics = {
        "mode": mode,
        "vote": vote,
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
    parser = argparse.ArgumentParser(description="Secure voter client")
    parser.add_argument(
        "--mode",
        choices=["dh", "ml_kem", "hybrid"],
        required=True,
        help="Key exchange mode",
    )
    parser.add_argument(
        "--auto-vote",
        choices=list(CANDIDATES.values()),
        help="Skip interactive prompt; cast this vote directly",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress logs; print one machine-readable metrics line",
    )
    args = parser.parse_args()

    try:
        vote = args.auto_vote if args.auto_vote else get_vote_from_user()
        metrics = cast_vote(args.mode, vote, quiet=args.quiet)

        if args.quiet:
            # Single line, key=val pairs, parseable by the benchmark script.
            print(",".join(f"{k}={v}" for k, v in metrics.items()))
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to the server. Is it running?", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[CLIENT] Cancelled.")


if __name__ == "__main__":
    main()