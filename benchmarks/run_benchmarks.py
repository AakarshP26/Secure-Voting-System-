"""
run_benchmarks.py — Automated benchmark harness for the secure voting system.

Spawns the server in each --mode, runs N client connections per mode,
captures per-run metrics, and writes them all to a CSV file.

Usage:
    python3.12 benchmarks/run_benchmarks.py --runs 30 --output benchmarks/results.csv

CSV columns:
    mode, run_id, connect_ms, handshake_ms, encrypt_send_ms,
    ack_ms, total_ms, bytes_sent_app, bytes_received_app

DESIGN NOTE
We spawn the server fresh for each (mode, run_id) so there is no warm-up
cache benefit and no carryover state between runs. This is the most
honest measurement methodology, though it slows DH benchmarks the most
(parameter regeneration each run). The paper will discuss this and also
report a faster "warm" variant if time permits.

Author: Aakarsh Prabhu
"""

import argparse
import csv
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_SCRIPT = REPO_ROOT / "src" / "server.py"
CLIENT_SCRIPT = REPO_ROOT / "src" / "client.py"
PYTHON = sys.executable

MODES = ["ml_kem", "hybrid", "dh"]   # Run fast modes first; DH last because slow.
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
    """
    Run client in --quiet mode and parse the metrics line it prints.
    Returns the metrics dict, or raises if the client failed.
    """
    proc = subprocess.run(
        [PYTHON, str(CLIENT_SCRIPT),
         "--mode", mode,
         "--auto-vote", "Bob",
         "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Client failed (rc={proc.returncode}): {proc.stderr}")

    # Output is a single line of key=val,key=val,...
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if not line:
        raise RuntimeError(f"Client produced no metrics line. stderr: {proc.stderr}")

    metrics = {}
    for kv in line.split(","):
        k, v = kv.split("=", 1)
        # Numeric where possible, else string.
        try:
            metrics[k] = float(v)
        except ValueError:
            metrics[k] = v
    return metrics


def benchmark_mode(mode: str, runs: int) -> list[dict]:
    """
    Run `runs` benchmark iterations for a single mode.

    Spawns a fresh server for EACH run for clean measurements.
    """
    results = []
    for i in range(runs):
        print(f"  [{mode}] run {i + 1}/{runs} ...", end="", flush=True)

        # Spawn server in background.
        server_proc = subprocess.Popen(
            [PYTHON, str(SERVER_SCRIPT), "--mode", mode],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # Wait until server is ready to accept connections.
            wait_for_server(timeout_s=120.0)

            # Run the client and get metrics.
            metrics = run_client(mode)
            metrics["run_id"] = i
            results.append(metrics)
            print(f" handshake={metrics['handshake_ms']:.1f}ms, total={metrics['total_ms']:.1f}ms")
        finally:
            # Always kill the server before the next run.
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark secure voting modes")
    parser.add_argument("--runs", type=int, default=30,
                        help="Number of runs per mode (default: 30)")
    parser.add_argument("--output", type=str, default="benchmarks/results.csv",
                        help="CSV output path")
    parser.add_argument("--modes", nargs="+", choices=MODES, default=MODES,
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

    # Write CSV — column set is the union of all metric keys.
    columns = ["mode", "run_id", "vote",
               "connect_ms", "handshake_ms", "encrypt_send_ms", "ack_ms",
               "total_ms", "bytes_sent_app", "bytes_received_app"]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in all_results:
            writer.writerow({k: row.get(k, "") for k in columns})

    print(f"\n[OK] Wrote {len(all_results)} rows to {output_path}")


if __name__ == "__main__":
    main()