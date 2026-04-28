"""
server_async.py — FastAPI + WebSocket Secure Chat Server (Phase 4)

Wraps the existing Phase 3 `server.py` logic in a FastAPI WebSocket endpoint.
Uses `WebSocketAdapter` to pass the async WebSocket into the synchronous crypto layer
without modifying the crypto or routing logic at all.

Usage:
    uvicorn backend.server_async:app --host 127.0.0.1 --port 65432
"""

import sys
import os
import threading
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db
from server import handle_client
from adapter import WebSocketAdapter

cached_dh_params = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    db.start()
    print("[DB] SQLite ready (WAL mode, single writer thread)")
    yield
    # Shutdown
    db.stop()

app = FastAPI(title="Secure Chat Server", lifespan=lifespan)

@app.websocket("/ws/{mode}")
async def websocket_endpoint(websocket: WebSocket, mode: str):
    if mode not in ["dh", "ml_kem", "hybrid"]:
        await websocket.close(code=1003, reason="Invalid mode")
        return

    await websocket.accept()
    addr = f"{websocket.client.host}:{websocket.client.port}"
    print(f"[+] WebSocket connection from {addr} (mode={mode})")

    adapter = WebSocketAdapter()

    # Run the existing synchronous handle_client logic in a background thread
    thread = threading.Thread(
        target=handle_client,
        args=(adapter, addr, mode, cached_dh_params),
        daemon=True,
    )
    thread.start()

    # Bridge WebSocket reads to the adapter's recv_queue
    async def ws_receiver():
        try:
            while True:
                data = await websocket.receive_bytes()
                adapter.recv_queue.put(data)
        except WebSocketDisconnect:
            pass
        except Exception as e:
            print(f"[-] WS receive error {addr}: {e}")
        finally:
            adapter.recv_queue.put(b"")  # Signal EOF to sync thread

    # Bridge the adapter's send_queue to WebSocket writes
    async def ws_sender():
        try:
            while True:
                # Run the blocking .get() in a threadpool so we don't block the event loop
                data = await asyncio.to_thread(adapter.send_queue.get)
                if data == b"":
                    break
                await websocket.send_bytes(data)
        except WebSocketDisconnect:
            pass
        except Exception as e:
            print(f"[-] WS send error {addr}: {e}")

    # Run both tasks until one finishes (e.g., EOF received or sent)
    receiver_task = asyncio.create_task(ws_receiver())
    sender_task = asyncio.create_task(ws_sender())
    
    try:
        done, pending = await asyncio.wait(
            [receiver_task, sender_task], 
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    except Exception:
        pass
    finally:
        print(f"[-] WebSocket closed {addr}")
