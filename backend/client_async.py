"""
client_async.py — Secure Chat Client (WebSocket Edition, Phase 4)

Connects to the FastAPI server using WebSockets. Wraps the Phase 3 `client.py` 
logic using `WebSocketAdapter` so the crypto layer works seamlessly over WS.

Usage:
    python backend/client_async.py --mode hybrid --user alice --password secret
"""
import sys
import os
import threading
import asyncio
import argparse
import websockets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from client import run_chat_client
from adapter import WebSocketAdapter

async def async_main(mode: str, username: str, password: str, recipient: str, message: str, quiet: bool):
    uri = f"ws://127.0.0.1:65432/ws/{mode}"
    
    adapter = WebSocketAdapter()
    
    try:
        async with websockets.connect(uri) as websocket:
            # Start sync client in thread
            result = {}
            
            def thread_target():
                result["metrics"] = run_chat_client(mode, username, password, recipient, message, quiet, adapter)
            
            thread = threading.Thread(target=thread_target, daemon=True)
            thread.start()

            async def ws_receiver():
                try:
                    while True:
                        data = await websocket.recv()
                        adapter.recv_queue.put(data)
                except websockets.exceptions.ConnectionClosed:
                    pass
                except Exception as e:
                    if not quiet:
                        print(f"[-] WS receive error: {e}")
                finally:
                    adapter.recv_queue.put(b"")

            async def ws_sender():
                try:
                    while True:
                        data = await asyncio.to_thread(adapter.send_queue.get)
                        if data == b"":
                            break
                        await websocket.send(data)
                except websockets.exceptions.ConnectionClosed:
                    pass
                except Exception as e:
                    if not quiet:
                        print(f"[-] WS send error: {e}")

            receiver_task = asyncio.create_task(ws_receiver())
            sender_task = asyncio.create_task(ws_sender())
            
            done, pending = await asyncio.wait(
                [receiver_task, sender_task], 
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
                
            return result.get("metrics")
    except ConnectionRefusedError:
        if not quiet:
            print("[!] Server not reachable.")
    except Exception as e:
        if not quiet:
            print(f"[!] WebSocket connection failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Secure chat client (WebSocket)")
    parser.add_argument("--mode", choices=["dh", "ml_kem", "hybrid"], required=True)
    parser.add_argument("--user",     required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--message",  help="Single message to send")
    parser.add_argument("--to",       default="server")
    parser.add_argument("--quiet",    action="store_true")
    args = parser.parse_args()

    try:
        asyncio.run(async_main(args.mode, args.user, args.password, args.to, args.message, args.quiet))
    except KeyboardInterrupt:
        print("\n[CLIENT] Cancelled.")

if __name__ == "__main__":
    main()
