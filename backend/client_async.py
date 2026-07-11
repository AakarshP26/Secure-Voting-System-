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


async def async_main(
    mode: str,
    username: str,
    password: str,
    recipient: str,
    message: str,
    quiet: bool,
) -> dict | None:
    uri = f"ws://127.0.0.1:65432/ws/{mode}"
    adapter = WebSocketAdapter()
    result: dict = {"metrics": None, "error": None}

    try:
        async with websockets.connect(uri) as websocket:

            def thread_target() -> None:
                try:
                    metrics = run_chat_client(
                        mode, username, password, recipient, message, quiet, adapter
                    )
                    if metrics is None:
                        result["error"] = (
                            "Authentication failed or the server rejected the message. "
                            "Check username/password."
                        )
                    else:
                        result["metrics"] = metrics
                except Exception as exc:
                    result["error"] = str(exc)

            thread = threading.Thread(target=thread_target, daemon=True)
            thread.start()

            async def ws_receiver() -> None:
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

            async def ws_sender() -> None:
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

            recv_task = asyncio.create_task(ws_receiver())
            send_task = asyncio.create_task(ws_sender())

            # Wait for the sync crypto client to finish before tearing down
            # the WebSocket bridge (avoids cancelling recv mid-handshake).
            await asyncio.to_thread(thread.join)

            for task in (recv_task, send_task):
                task.cancel()
            await asyncio.gather(recv_task, send_task, return_exceptions=True)

    except ConnectionRefusedError:
        raise ConnectionError(
            "Cannot reach backend at 127.0.0.1:65432. "
            "Start it with: uvicorn backend.server_async:app --host 127.0.0.1 --port 65432"
        ) from None
    except Exception as e:
        if not quiet:
            print(f"[!] WebSocket connection failed: {e}")
        raise

    if result["error"]:
        raise RuntimeError(result["error"])
    return result["metrics"]


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
        metrics = asyncio.run(
            async_main(args.mode, args.user, args.password, args.to, args.message, args.quiet)
        )
        if args.quiet and metrics:
            print(",".join(f"{k}={v}" for k, v in metrics.items()))
    except (ConnectionError, RuntimeError) as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[CLIENT] Cancelled.")


if __name__ == "__main__":
    main()
