"""
run_benchmarks.py — Automated benchmark harness for the secure voting system.

Spawns the server in each --mode, runs N client connections per mode,
captures per-run metrics, and writes them all to a CSV file.

Usage:
    python3.12 benchmarks/run_benchmarks.py --runs 30 --output benchmarks/results.csv
    python3.12 benchmarks/run_benchmarks.py --modes dh_cached --runs 30 --output benchmarks/results_cached.csv

The "dh_cached" pseudo-mode runs DH but launches the server with
--cache-params for realistic deployment measurement.

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
SERVER_SCRIPT = REPO_ROOT / "src" / "server.py"
CLIENT_SCRIPT = REPO_ROOT / "src" / "client.py"
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
    actual_mode = "dh" if mode == "dh_cached" else mode
    proc = subprocess.run(
        [PYTHON, str(CLIENT_SCRIPT),
         "--mode", actual_mode,
         "--auto-vote", "Bob",
         "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Client failed (rc={proc.returncode}): {proc.stderr}")

    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if not line:
        raise RuntimeError(f"Client produced no metrics line. stderr: {proc.stderr}")

    metrics = {}
    for kv in line.split(","):
        k, v = kv.split("=", 1)
        try:
            metrics[k] = float(v)
        except ValueError:
            metrics[k] = v
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

        # Build server command line — dh_cached spawns DH server with --cache-params.
        actual_mode = "dh" if mode == "dh_cached" else mode
        server_args = [PYTHON, str(SERVER_SCRIPT), "--mode", actual_mode]
        if mode == "dh_cached":
            server_args.append("--cache-params")

        server_proc = subprocess.Popen(
            server_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # For dh_cached, wait longer because the server pre-generates params at startup.
            timeout = 120.0 if mode == "dh_cached" else 60.0
            wait_for_server(timeout_s=timeout)

            metrics = run_client(mode)
            metrics["run_id"] = i
            results.append(metrics)
            print(f" handshake={metrics['handshake_ms']:.1f}ms, total={metrics['total_ms']:.1f}ms")
        finally:
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