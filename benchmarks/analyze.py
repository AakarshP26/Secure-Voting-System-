"""
analyze.py — Print summary statistics from benchmark results.

Usage:
    python3.12 benchmarks/analyze.py benchmarks/results.csv

Prints, per mode, mean/median/p95/min/max for every numeric metric.
"""

import argparse
import csv
import statistics
from collections import defaultdict


METRICS_TO_REPORT = [
    "connect_ms",
    "handshake_ms",
    "encrypt_send_ms",
    "ack_ms",
    "total_ms",
    "bytes_sent_app",
    "bytes_received_app",
]


def percentile(values: list[float], pct: float) -> float:
    """Compute pth percentile of `values` (0 < pct < 100)."""
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path")
    args = parser.parse_args()

    by_mode: dict[str, list[dict]] = defaultdict(list)
    with open(args.csv_path) as f:
        for row in csv.DictReader(f):
            by_mode[row["mode"]].append(row)

    for mode, rows in by_mode.items():
        print(f"\n=== {mode}  (n={len(rows)}) ===")
        for metric in METRICS_TO_REPORT:
            try:
                values = [float(r[metric]) for r in rows if r.get(metric) not in (None, "")]
            except ValueError:
                continue
            if not values:
                continue
            print(
                f"  {metric:<22} "
                f"mean={statistics.mean(values):>10.3f}  "
                f"median={statistics.median(values):>10.3f}  "
                f"p95={percentile(values, 95):>10.3f}  "
                f"min={min(values):>10.3f}  "
                f"max={max(values):>10.3f}"
            )


if __name__ == "__main__":
    main()