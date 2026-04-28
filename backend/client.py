"""
client.py — Secure Chat Client (backend) — Phase 2

Flow:
  1. TCP connect
  2. Send mode marker
  3. Key exchange (DH / ML-KEM / Hybrid)
  4. Send encrypted AUTH payload (username + password)
  5. Receive encrypted token ACK
  6. Send encrypted CHAT payload (structured JSON)
  7. Receive encrypted delivered ACK

Usage:
    python backend/client.py --mode hybrid --user alice --password secret --message "Hello"
    python backend/client.py --mode ml_kem --user bob --password pw --message "Hi" --quiet

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
import protocol as proto


HOST = "127.0.0.1"
PORT = 65432


def send_secure_message(mode: str, username: str, password: str,
                         recipient: str, message: str,
                         quiet: bool = False) -> dict:
    """
    Full secure message flow with authentication.
    Returns timing + byte metrics dict.
    """
    bytes_sent = 0
    bytes_recv = 0

    def log(msg: str) -> None:
        if not quiet:
            print(msg)

    t0 = time.perf_counter_ns()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        log(f"[CLIENT] Connecting to {HOST}:{PORT} (mode={mode})...")
        s.connect((HOST, PORT))
        t_connected = time.perf_counter_ns()

        # ── Mode marker ───────────────────────────────────────────
        mode_bytes = mode.encode("utf-8")
        send_msg(s, mode_bytes)
        bytes_sent += 4 + len(mode_bytes)

        # ── Key exchange ──────────────────────────────────────────
        handler = get_handler(mode)
        t_kex_start = time.perf_counter_ns()
        shared_secret = handler.client_side(s)
        t_kex_end = time.perf_counter_ns()
        aes_key = derive_aes_key(shared_secret)
        log(f"[OK] Key exchange done ({len(shared_secret)}B raw secret)")

        # ── Authentication ────────────────────────────────────────
        auth_payload = proto.build_auth(username, password)
        auth_enc = aes_encrypt(aes_key, proto.encode(auth_payload))
        send_msg(s, auth_enc)
        bytes_sent += 4 + len(auth_enc)
        log(f"[CLIENT] Sent AUTH for user '{username}'")

        raw_auth_ack = recv_msg(s)
        bytes_recv += 4 + len(raw_auth_ack)
        auth_ack = proto.decode(aes_decrypt(aes_key, raw_auth_ack))

        if auth_ack.get("type") == proto.MsgType.ERROR:
            print(f"[ERROR] Auth failed: {auth_ack.get('data')}", file=sys.stderr)
            sys.exit(1)

        token = auth_ack.get("token", "")
        log(f"[CLIENT] Authenticated. Token: {token[:12]}...")
        t_auth_done = time.perf_counter_ns()

        # ── Send chat message ─────────────────────────────────────
        chat_payload = proto.build_chat(username, recipient, message)
        chat_enc = aes_encrypt(aes_key, proto.encode(chat_payload))
        send_msg(s, chat_enc)
        bytes_sent += 4 + len(chat_enc)
        t_send_done = time.perf_counter_ns()
        log(f"[CLIENT] Sent message ({len(chat_enc)}B encrypted)")

        # ── Receive delivered ACK ─────────────────────────────────
        raw_ack = recv_msg(s)
        bytes_recv += 4 + len(raw_ack)
        ack = proto.decode(aes_decrypt(aes_key, raw_ack))
        t_ack = time.perf_counter_ns()

        if ack.get("type") == proto.MsgType.ERROR:
            print(f"[ERROR] Server rejected: {ack.get('data')}", file=sys.stderr)
            sys.exit(1)

        log(f"[CLIENT] Server ACK: status={ack.get('status')} ref={ack.get('ref_id','')[:8]}")

    t_end = time.perf_counter_ns()

    return {
        "mode":               mode,
        "message_id":         chat_payload["message_id"],
        "connect_ms":         (t_connected - t0) / 1e6,
        "handshake_ms":       (t_kex_end - t_kex_start) / 1e6,
        "auth_ms":            (t_auth_done - t_kex_end) / 1e6,
        "encrypt_send_ms":    (t_send_done - t_auth_done) / 1e6,
        "ack_ms":             (t_ack - t_send_done) / 1e6,
        "total_ms":           (t_end - t0) / 1e6,
        "bytes_sent_app":     bytes_sent,
        "bytes_received_app": bytes_recv,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure chat client")
    parser.add_argument("--mode", choices=["dh", "ml_kem", "hybrid"], required=True)
    parser.add_argument("--user",     required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--message",  required=True, help="Message to send")
    parser.add_argument("--to",       default="server", help="Recipient username")
    parser.add_argument("--quiet",    action="store_true")
    args = parser.parse_args()

    try:
        metrics = send_secure_message(
            mode=args.mode,
            username=args.user,
            password=args.password,
            recipient=args.to,
            message=args.message,
            quiet=args.quiet,
        )
        if args.quiet:
            print(",".join(f"{k}={v}" for k, v in metrics.items()))
    except ConnectionRefusedError:
        print("[ERROR] Server not reachable.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[CLIENT] Cancelled.")


if __name__ == "__main__":
    main()