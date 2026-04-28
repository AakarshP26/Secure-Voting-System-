"""
adapter.py — Bridges synchronous TCP crypto calls to async WebSockets.

WHY THIS EXISTS
---------------
Our existing crypto layer (kex_handlers.py) and framing (utils/protocol.py) 
expect a raw, blocking `socket.socket` with `sendall()` and `recv()`.

In Phase 4, we are moving to FastAPI and WebSockets (`async/await`).
We strictly DO NOT want to rewrite our proven crypto layer into async code. 
Instead, we provide this adapter. It exposes the `.sendall()` and `.recv()` 
methods the crypto layer expects, but internally routes those bytes through 
thread-safe queues to the async event loop handling the WebSocket.

This preserves the 4-byte TCP framing over WebSockets. While WebSockets have 
their own framing, passing our raw TCP frames as binary WebSocket payloads 
ensures the crypto layer bytes remain exactly the same.
"""

import queue

class WebSocketAdapter:
    def __init__(self):
        self.recv_queue = queue.Queue()
        self.send_queue = queue.Queue()
        self.buffer = bytearray()

    def sendall(self, data: bytes) -> None:
        """Called by synchronous crypto code to send data."""
        self.send_queue.put(data)

    def recv(self, n: int) -> bytes:
        """Called by synchronous crypto code to read exactly n bytes."""
        while len(self.buffer) < n:
            chunk = self.recv_queue.get()
            if chunk == b"":  # EOF sentinel
                if len(self.buffer) == 0:
                    return b""
                break
            self.buffer.extend(chunk)
        
        res = bytes(self.buffer[:n])
        self.buffer = self.buffer[n:]
        return res

    def close(self) -> None:
        """Called by synchronous crypto code when closing the connection."""
        self.recv_queue.put(b"")
        self.send_queue.put(b"")
