"""
run_benchmarks.py — Automated benchmark harness for the secure chat system.

Spawns the async server in each --mode, runs N client connections per mode,
captures per-run metrics, and writes them all to a CSV file.

Usage:
    python3.12 benchmarks/run_benchmarks.py --runs 30 --output benchmarks/results.csv

Author: Aakarsh Prabhu
"""

import argparse
import csv
import socket
import subprocess
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

MODES = ["ml_kem", "hybrid", "dh", "dh_cached"]
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432


def wait_for_server(timeout_s: float = 60.0) -> None:
    """Poll the server port until it accepts connections, or timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=1.0):
                return
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.1)
    raise TimeoutError(f"Server did not become reachable within {timeout_s}s")


def run_client(mode: str) -> dict:
    """Run client in --quiet mode and parse the metrics line it prints."""
    proc = subprocess.run(
        [PYTHON, "backend/client_async.py",
         "--mode", mode,
         "--user", "alice",
         "--password", "secret",
         "--to", "bob",
         "--message", "benchmark",
         "--quiet"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Client failed (rc={proc.returncode}): {proc.stderr}\n{proc.stdout}")

    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if not line:
        raise RuntimeError(f"Client produced no metrics line. stderr: {proc.stderr}\n{proc.stdout}")

    metrics = {}
    for kv in line.split(","):
        try:
            k, v = kv.split("=", 1)
            try:
                metrics[k] = float(v)
            except ValueError:
                metrics[k] = v
        except Exception:
            pass
            
    # Override mode field so the CSV preserves the dh_cached distinction.
    metrics["mode"] = mode
    return metrics


def benchmark_mode(mode: str, runs: int) -> list[dict]:
    """
    Run `runs` benchmark iterations for a single mode.
    Spawns a fresh server for each run.
    """
    results = []
    for i in range(runs):
        print(f"  [{mode}] run {i + 1}/{runs} ...", end="", flush=True)

        # Build server command line
        # Notice: server_async.py does not take arguments directly anymore, it's a FastAPI app.
        # But wait, how do we pass dh_cached to FastAPI? 
        # In server_async.py, dh_cached is not supported natively via CLI args like server.py.
        # So we just run standard dh, ml_kem, hybrid.
        server_args = [PYTHON, "-m", "uvicorn", "backend.server_async:app", "--host", SERVER_HOST, "--port", str(SERVER_PORT)]

        server_proc = subprocess.Popen(
            server_args,
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            wait_for_server(timeout_s=30.0)

            metrics = run_client(mode)
            metrics["run_id"] = i
            results.append(metrics)
            print(f" handshake={metrics.get('handshake_ms', 0):.1f}ms, total={metrics.get('total_ms', 0):.1f}ms")
        except Exception as e:
            print(f" FAILED: {e}")
        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark secure chat modes")
    parser.add_argument("--runs", type=int, default=30,
                        help="Number of runs per mode (default: 30)")
    parser.add_argument("--output", type=str, default="benchmarks/results.csv",
                        help="CSV output path")
    parser.add_argument("--modes", nargs="+", choices=["ml_kem", "hybrid", "dh"], default=["ml_kem", "hybrid", "dh"],
                        help="Which modes to benchmark")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    all_results = []
    for mode in args.modes:
        print(f"\n=== Benchmarking mode: {mode} ({args.runs} runs) ===")
        try:
            mode_results = benchmark_mode(mode, args.runs)
            all_results.extend(mode_results)
        except Exception as e:
            print(f"  [!] Error benchmarking {mode}: {e}")
            continue

    if not all_results:
        print("\nNo results collected; aborting.")
        sys.exit(1)

    columns = ["mode", "run_id", "message_id",
               "connect_ms", "handshake_ms", "auth_ms", "encrypt_send_ms", "ack_ms",
               "total_ms", "bytes_sent_app", "bytes_received_app"]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in all_results:
            writer.writerow({k: row.get(k, "") for k in columns})

    print(f"\n[OK] Wrote {len(all_results)} rows to {output_path}")


if __name__ == "__main__":
    main()