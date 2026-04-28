import asyncio
import os
import sys
import time
import websockets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend import protocol as proto
from backend.crypto.aes import encrypt, decrypt
from backend.crypto.kex_handlers import get_handler
from backend.crypto.kdf import derive_aes_key
from backend.adapter import WebSocketAdapter

async def main():
    mode = "hybrid"
    user = "alice"
    pw = "secret"
    host = "127.0.0.1"
    uri = f"ws://{host}:65432/ws/{mode}"
    
    print(f"[*] Connecting to {uri} to simulate replay attack...")
    try:
        async with websockets.connect(uri) as ws:
            adapter = WebSocketAdapter(ws)
            
            # Key exchange
            handler = get_handler(mode)
            shared_secret = handler.client_side(adapter)
            aes_key = derive_aes_key(shared_secret)
            
            # Auth
            auth_payload = proto.build_auth(user, pw)
            auth_enc = encrypt(aes_key, proto.encode(auth_payload))
            adapter.sendall(len(auth_enc).to_bytes(4, 'big') + auth_enc)
            
            raw_len = adapter.recv(4)
            if len(raw_len) < 4: return
            msg_len = int.from_bytes(raw_len, 'big')
            raw_auth_ack = adapter.recv(msg_len)
            
            auth_ack = proto.decode(decrypt(aes_key, raw_auth_ack))
            if auth_ack.get("type") == proto.MsgType.ERROR:
                print("[-] Authentication failed.")
                return
            
            print("[+] Authentication successful.")
            
            # Construct a valid message
            chat_payload = proto.build_chat(user, "bob", "This is the original message.")
            enc_payload = encrypt(aes_key, proto.encode(chat_payload))
            
            print(f"[*] Sending original message (ID: {chat_payload['message_id']})...")
            adapter.sendall(len(enc_payload).to_bytes(4, 'big') + enc_payload)
            
            # We skip waiting for ACK for simplicity and immediately replay
            print(f"[*] Attempting REPLAY attack with same payload...")
            adapter.sendall(len(enc_payload).to_bytes(4, 'big') + enc_payload)
            
            # Read responses
            for _ in range(2):
                raw_len = adapter.recv(4)
                if not raw_len:
                    print("[+] Replay was BLOCKED by the server! (Connection closed)")
                    break
                msg_len = int.from_bytes(raw_len, 'big')
                raw_ack = adapter.recv(msg_len)
                ack = proto.decode(decrypt(aes_key, raw_ack))
                if ack.get("type") == proto.MsgType.ERROR:
                    print(f"[+] Server rejected: {ack.get('data')}")
            
    except Exception as e:
        print(f"[-] Disconnected: {e}")

if __name__ == "__main__":
    asyncio.run(main())
