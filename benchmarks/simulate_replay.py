import asyncio
import os
import sys
import time
import websockets
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.client_async import authenticate
from backend.utils.protocol import SecureProtocol, MsgType
from backend.crypto.aes import encrypt

async def main():
    mode = "hybrid"
    user = "alice"
    pw = "secret"
    host = "127.0.0.1"
    uri = f"ws://{host}:65432/ws/{mode}"
    
    print(f"[*] Connecting to {uri} to simulate replay attack...")
    try:
        async with websockets.connect(uri) as ws:
            aes_key = await authenticate(ws, mode, user, pw)
            if not aes_key:
                print("[-] Authentication failed.")
                return
                
            print("[+] Authentication successful.")
            
            # Construct a valid message
            proto = SecureProtocol()
            msg_id = os.urandom(8).hex()
            payload = {
                "type": MsgType.CHAT,
                "from": user,
                "to": "bob",
                "message_id": msg_id,
                "timestamp": int(time.time()),
                "data": "This is the original message."
            }
            
            enc_payload = encrypt(aes_key, proto.encode(payload))
            
            print(f"[*] Sending original message (ID: {msg_id})...")
            await ws.send(enc_payload)
            
            # Wait for ACK
            raw_ack = await ws.recv()
            print(f"[+] Server accepted original message.")
            
            print(f"[*] Attempting REPLAY attack with same payload...")
            await ws.send(enc_payload)
            
            # The server should drop it or send an error
            try:
                raw_ack2 = await ws.recv()
                # If we get an ACK, it might be an error ACK. We can't decrypt it easily without the protocol wrapper, 
                # but if the connection is closed or error returned, we know it worked.
                print("[-] Replay was NOT blocked (this is bad if it happens).")
            except websockets.exceptions.ConnectionClosed:
                print("[+] Replay was BLOCKED by the server! (Connection closed / Error returned)")
                
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
