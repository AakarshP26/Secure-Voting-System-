"""
server.py — Secure Chat Server (backend) — Phase 2

Phases completed in this file:
  Phase 0: backend/ directory, JSON payloads, structured ACKs
  Phase 1: protocol.py schema (MsgType, builder helpers, validate)
  Phase 2: SQLite persistence (db.py), bcrypt auth (auth.py),
           replay protection with timestamp + message_id window

Flow per connection:
  1. Read mode marker, validate
  2. Hybrid/ML-KEM/DH key exchange -> shared secret
  3. Derive AES-256 key via HKDF-SHA256
  4. Receive encrypted AUTH payload, verify username + password
     -> issue session token, send encrypted token ACK
  5. Receive encrypted CHAT payload:
     a. Validate JSON schema
     b. Check timestamp (reject if > 5 min old)
     c. Check message_id in seen_messages (reject replays)
     d. Persist message to DB
     e. Send encrypted delivered ACK

Usage:
    python backend/server.py --mode hybrid
    python backend/server.py --mode ml_kem
    python backend/server.py --mode dh --cache-params

Author: Aakarsh Prabhu
"""

import argparse
import socket
import sys
import threading
import time

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.kex_handlers import get_handler
from crypto.kdf import derive_aes_key
from crypto.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from utils.protocol import send_msg, recv_msg
import protocol as proto
import db
import auth


HOST = "127.0.0.1"
PORT = 65432
TIMESTAMP_WINDOW = 300   # 5 minutes — reject messages older than this


# ------------------------------------------------------------------
# Per-client handler
# ------------------------------------------------------------------

def handle_client(conn: socket.socket, addr: tuple, mode: str,
                  cached_dh_params=None) -> None:
    print(f"[+] Connection from {addr} (mode={mode})")
    try:
        # ── 1. Mode handshake ─────────────────────────────────────
        client_mode = recv_msg(conn).decode("utf-8")
        if client_mode != mode:
            send_msg(conn, proto.encode(
                proto.build_error(proto.ErrCode.MODE_MISMATCH,
                                  f"server={mode}, client={client_mode}")))
            return

        # ── 2. Key exchange ───────────────────────────────────────
        handler = get_handler(mode)
        if mode == "dh" and cached_dh_params is not None:
            handler.cached_params = cached_dh_params
        shared_secret = handler.server_side(conn)
        aes_key = derive_aes_key(shared_secret)
        print(f"[OK] {addr} — key exchange done ({len(shared_secret)}B secret)")

        # ── 3. Authentication ─────────────────────────────────────
        raw_auth = recv_msg(conn)
        auth_payload = proto.decode(aes_decrypt(aes_key, raw_auth))

        err = proto.validate(auth_payload)
        if err:
            send_msg(conn, aes_encrypt(aes_key, proto.encode(
                proto.build_error(proto.ErrCode.INVALID_SCHEMA, err))))
            return

        if auth_payload["type"] != proto.MsgType.AUTH:
            send_msg(conn, aes_encrypt(aes_key, proto.encode(
                proto.build_error(proto.ErrCode.AUTH_FAILED,
                                  "Expected AUTH message first"))))
            return

        username = auth_payload["from"]
        password = auth_payload["data"]
        token, err_msg = auth.login(username, password)

        if not token:
            send_msg(conn, aes_encrypt(aes_key, proto.encode(
                proto.build_error(proto.ErrCode.AUTH_FAILED, err_msg))))
            return

        # Send token back inside an ACK (encrypted)
        ack_with_token = proto.build_ack(auth_payload["message_id"], status="authenticated")
        ack_with_token["token"] = token
        send_msg(conn, aes_encrypt(aes_key, proto.encode(ack_with_token)))
        print(f"[AUTH] {addr} authenticated as '{username}'")

        # ── 4. Receive and process CHAT message ───────────────────
        raw_msg = recv_msg(conn)
        payload = proto.decode(aes_decrypt(aes_key, raw_msg))

        # Schema validation
        err = proto.validate(payload)
        if err:
            send_msg(conn, aes_encrypt(aes_key, proto.encode(
                proto.build_error(proto.ErrCode.INVALID_SCHEMA, err))))
            return

        # Timestamp window check (replay protection layer 1)
        age = time.time() - payload["timestamp"]
        if age > TIMESTAMP_WINDOW or age < -30:   # allow 30s clock skew
            send_msg(conn, aes_encrypt(aes_key, proto.encode(
                proto.build_error(proto.ErrCode.EXPIRED,
                                  f"Message age {age:.1f}s exceeds window"))))
            return

        # message_id uniqueness check (replay protection layer 2)
        msg_id = payload["message_id"]
        if db.is_replay(msg_id):
            send_msg(conn, aes_encrypt(aes_key, proto.encode(
                proto.build_error(proto.ErrCode.REPLAY,
                                  f"message_id {msg_id} already seen"))))
            return

        # Mark seen and persist
        db.record_seen(msg_id)
        db.insert_message(
            message_id=msg_id,
            sender=payload["from"],
            recipient=payload.get("to", "server"),
            plaintext=payload["data"],
            created_at=payload["timestamp"],
        )
        print(f"[MSG] {username} -> {payload.get('to','server')}: {payload['data']!r}")

        # Send delivered ACK
        db.update_delivery_status(msg_id, "delivered")
        send_msg(conn, aes_encrypt(aes_key, proto.encode(
            proto.build_ack(msg_id, status="delivered"))))

    except Exception as e:
        print(f"[!] Error with {addr}: {type(e).__name__}: {e}")
    finally:
        conn.close()
        print(f"[-] Closed {addr}")


# ------------------------------------------------------------------
# Server bootstrap
# ------------------------------------------------------------------

def start_server(mode: str, cache_params: bool = False) -> None:
    # Start the database (schema + writer thread)
    db.start()
    print("[DB] SQLite ready (chat.db, WAL mode, single writer thread)")

    cached_dh_params = None
    if mode == "dh" and cache_params:
        from crypto.dh import generate_parameters as dh_gen
        print("[SERVER] Pre-generating DH parameters (~30s)...")
        cached_dh_params = dh_gen(key_size=2048)
        print("[SERVER] DH parameters ready.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        note = " (DH cached)" if cached_dh_params else ""
        print(f"[SERVER] Listening on {HOST}:{PORT} (mode={mode}){note}")

        while True:
            conn, addr = s.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, addr, mode, cached_dh_params),
                daemon=True,
            ).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure chat server")
    parser.add_argument("--mode", choices=["dh", "ml_kem", "hybrid"],
                        required=True)
    parser.add_argument("--cache-params", action="store_true")
    args = parser.parse_args()

    try:
        start_server(args.mode, cache_params=args.cache_params)
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down")
        db.stop()


if __name__ == "__main__":
    main()