"""
plot.py — Generate paper figures from the combined benchmark CSV.

Produces two PNGs into docs/paper/figures/:
  1. handshake_latency.png   — grouped bar chart of median handshake_ms
  2. handshake_distribution.png — boxplot showing variance per mode

Usage:
    python3.12 benchmarks/plot.py benchmarks/results_all.csv

Both plots use a log Y-axis so DH (fresh) at ~10s coexists visually
with sub-millisecond ML-KEM measurements.
"""

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


# Display order from "fastest expected" to "slowest expected"
MODE_ORDER = ["ml_kem", "hybrid", "dh_cached", "dh"]
MODE_LABELS = {
    "ml_kem":    "ML-KEM-768\n(post-quantum)",
    "hybrid":    "Hybrid\n(X25519 + ML-KEM-768)",
    "dh_cached": "DH-2048\n(cached params)",
    "dh":        "DH-2048\n(fresh params)",
}
MODE_COLORS = {
    "ml_kem":    "#2ca02c",   # green — recommended PQ
    "hybrid":    "#1f77b4",   # blue  — recommended hybrid
    "dh_cached": "#ff7f0e",   # orange — classical, realistic
    "dh":        "#d62728",   # red   — classical, worst case
}


def plot_median_bars(df: pd.DataFrame, out_path: Path) -> None:
    """Bar chart: median handshake latency per mode (log scale)."""
    fig, ax = plt.subplots(figsize=(8, 5))

    medians = []
    p95s = []
    labels = []
    colors = []
    for mode in MODE_ORDER:
        mode_df = df[df["mode"] == mode]
        if mode_df.empty:
            continue
        medians.append(mode_df["handshake_ms"].median())
        p95s.append(mode_df["handshake_ms"].quantile(0.95))
        labels.append(MODE_LABELS[mode])
        colors.append(MODE_COLORS[mode])

    x = list(range(len(labels)))
    ax.bar(x, medians, color=colors, edgecolor="black", linewidth=0.6,
           label="Median")
    ax.scatter(x, p95s, marker="D", color="black", s=40, zorder=3,
               label="p95")

    # Annotate each bar with its median value.
    for xi, m in zip(x, medians):
        if m >= 1000:
            text = f"{m:.0f} ms"
        elif m >= 1:
            text = f"{m:.2f} ms"
        else:
            text = f"{m:.3f} ms"
        ax.text(xi, m * 1.15, text, ha="center", va="bottom", fontsize=9)

    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Handshake latency (ms, log scale)")
    ax.set_title("Key Exchange Handshake Latency by Mode")
    ax.grid(axis="y", which="both", linestyle=":", alpha=0.5)
    ax.legend(loc="upper left")

    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    print(f"[OK] Saved {out_path}")
    plt.close()


def plot_distribution_boxes(df: pd.DataFrame, out_path: Path) -> None:
    """Boxplot: distribution of handshake_ms per mode (log Y)."""
    fig, ax = plt.subplots(figsize=(8, 5))

    data = []
    labels = []
    colors = []
    for mode in MODE_ORDER:
        mode_df = df[df["mode"] == mode]
        if mode_df.empty:
            continue
        data.append(mode_df["handshake_ms"].values)
        labels.append(MODE_LABELS[mode])
        colors.append(MODE_COLORS[mode])

    bp = ax.boxplot(data, labels=labels, patch_artist=True, widths=0.55,
                    flierprops=dict(marker="o", markersize=4, alpha=0.6))
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
        patch.set_edgecolor("black")

    ax.set_yscale("log")
    ax.set_ylabel("Handshake latency (ms, log scale)")
    ax.set_title("Handshake Latency Distribution (n=30 per mode)")
    ax.grid(axis="y", which="both", linestyle=":", alpha=0.5)

    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    print(f"[OK] Saved {out_path}")
    plt.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path")
    parser.add_argument("--out-dir", default="docs/paper/figures",
                        help="Output directory for PNGs")
    args = parser.parse_args()

    df = pd.read_csv(args.csv_path)
    print(f"Loaded {len(df)} rows. Modes present: "
          f"{sorted(df['mode'].unique())}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plot_median_bars(df, out_dir / "handshake_latency.png")
    plot_distribution_boxes(df, out_dir / "handshake_distribution.png")


if __name__ == "__main__":
    main()