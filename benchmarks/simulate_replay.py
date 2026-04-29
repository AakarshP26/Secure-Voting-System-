import asyncio
import os
import sys
import time
import websockets

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(repo_root, "backend")
sys.path.insert(0, backend_dir)

import protocol as proto
from crypto.aes import encrypt, decrypt
from crypto.kex_handlers import get_handler
from crypto.kdf import derive_aes_key
from adapter import WebSocketAdapter

async def ws_sender(ws, adapter):
    print("[DEBUG] Sender task started")
    while True:
        data = await asyncio.to_thread(adapter.send_queue.get)
        if data == b"": 
            print("[DEBUG] Sender task received EOF")
            break
        print(f"[DEBUG] Sending {len(data)} bytes to server")
        await ws.send(data)

async def ws_receiver(ws, adapter):
    print("[DEBUG] Receiver task started")
    try:
        async for message in ws:
            if isinstance(message, str): message = message.encode()
            print(f"[DEBUG] Received {len(message)} bytes from server")
            adapter.recv_queue.put(message)
    except Exception as e:
        print(f"[DEBUG] Receiver task error: {e}")
    finally:
        print("[DEBUG] Receiver task shutting down")
        adapter.recv_queue.put(b"")

async def main():
    mode = "hybrid"
    user = "alice"
    pw = "secret"
    host = "127.0.0.1"
    uri = f"ws://{host}:65432/ws/{mode}"
    
    print(f"[*] Connecting to {uri} to simulate replay attack...")
    try:
        async with websockets.connect(uri) as ws:
            adapter = WebSocketAdapter()
            sender_task = asyncio.create_task(ws_sender(ws, adapter))
            receiver_task = asyncio.create_task(ws_receiver(ws, adapter))
            
            # Run the synchronous logic in a thread
            def sync_test():
                try:
                    print("[DEBUG] Sync test started")
                    # 1. Mode handshake
                    print(f"[DEBUG] Sending mode handshake: {mode}")
                    adapter.sendall(len(mode).to_bytes(4, 'big') + mode.encode("utf-8"))

                    # 2. Key exchange
                    handler = get_handler(mode)
                    print("[DEBUG] Performing key exchange...")
                    shared_secret = handler.client_side(adapter)
                    aes_key = derive_aes_key(shared_secret)
                    print("[DEBUG] Key exchange successful")
                    
                    # Auth
                    auth_payload = proto.build_auth(user, pw)
                    auth_enc = encrypt(aes_key, proto.encode(auth_payload))
                    print(f"[DEBUG] Sending AUTH ({len(auth_enc)} bytes)")
                    adapter.sendall(len(auth_enc).to_bytes(4, 'big') + auth_enc)
                    
                    print("[DEBUG] Waiting for AUTH ACK...")
                    raw_len = adapter.recv(4)
                    if len(raw_len) < 4: 
                        print(f"[DEBUG] AUTH ACK length too short: {raw_len}")
                        return
                    msg_len = int.from_bytes(raw_len, 'big')
                    raw_auth_ack = adapter.recv(msg_len)
                    
                    auth_ack = proto.decode(decrypt(aes_key, raw_auth_ack))
                    if auth_ack.get("type") == proto.MsgType.ERROR:
                        print(f"[-] Authentication failed: {auth_ack.get('data')}")
                        return
                    
                    print("[+] Authentication successful.")
                    
                    # Construct a valid message
                    chat_payload = proto.build_chat(user, "bob", "This is the original message.")
                    enc_payload = encrypt(aes_key, proto.encode(chat_payload))
                    
                    print(f"[*] Sending original message (ID: {chat_payload['message_id']})...")
                    adapter.sendall(len(enc_payload).to_bytes(4, 'big') + enc_payload)
                    
                    # Replay
                    print(f"[*] Attempting REPLAY attack with same payload...")
                    adapter.sendall(len(enc_payload).to_bytes(4, 'big') + enc_payload)
                    
                    # Read responses
                    print("[DEBUG] Waiting for responses to original and replay...")
                    for i in range(2):
                        print(f"[DEBUG] Waiting for response {i+1}/2...")
                        raw_len = adapter.recv(4)
                        if not raw_len: 
                            print(f"[DEBUG] Response {i+1} received EOF")
                            break
                        msg_len = int.from_bytes(raw_len, 'big')
                        raw_ack = adapter.recv(msg_len)
                        ack = proto.decode(decrypt(aes_key, raw_ack))
                        if ack.get("type") == proto.MsgType.ERROR:
                            print(f"[+] Server rejected: {ack.get('data')}")
                        elif ack.get("type") == proto.MsgType.ACK:
                            print(f"[+] Server accepted: {ack.get('status')}")
                except Exception as e:
                    print(f"[DEBUG] Sync test exception: {e}")
                finally:
                    print("[DEBUG] Sync test closing adapter")
                    adapter.close()

            await asyncio.to_thread(sync_test)
            await sender_task
            await receiver_task
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
