"""
dashboard.py — Live benchmark dashboard for the Post-Quantum Secure Messaging Testbed.

Reads the CSV output of ``benchmarks/run_benchmarks.py`` and renders an
interactive comparison of classical vs. post-quantum key exchange performance.
Pure presentation layer: no crypto, no network — safe to import from app.py.
"""
from __future__ import annotations

import os

import altair as alt
import pandas as pd
import streamlit as st

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Ordered so the classical → post-quantum story reads left-to-right.
MODE_META = {
    "dh": {"label": "DH-2048", "sub": "Classical", "color": "#ef4444", "pqc": False},
    "dh_cached": {"label": "DH-2048 (cached)", "sub": "Classical", "color": "#f59e0b", "pqc": False},
    "ml_kem": {"label": "ML-KEM-768", "sub": "Post-Quantum", "color": "#22c55e", "pqc": True},
    "hybrid": {"label": "Hybrid", "sub": "X25519 + ML-KEM", "color": "#8b5cf6", "pqc": True},
}
MODE_ORDER = list(MODE_META.keys())
STAGE_COLS = ["connect_ms", "handshake_ms", "encrypt_send_ms", "ack_ms"]
STAGE_LABELS = {
    "connect_ms": "Connect",
    "handshake_ms": "Key exchange",
    "encrypt_send_ms": "Encrypt + send",
    "ack_ms": "ACK round-trip",
}


@st.cache_data(show_spinner=False)
def load_results() -> pd.DataFrame:
    """Load the widest available benchmark CSV, most-complete first."""
    for name in ("results_all.csv", "results.csv", "results_dhcached.csv"):
        path = os.path.join(_ROOT, "benchmarks", name)
        if os.path.exists(path):
            df = pd.read_csv(path)
            df = df[df["mode"].isin(MODE_META)].copy()
            if not df.empty:
                return df
    return pd.DataFrame()


def _label(mode: str) -> str:
    return MODE_META.get(mode, {}).get("label", mode)


def _color_scale(modes: list[str]) -> alt.Scale:
    return alt.Scale(
        domain=[_label(m) for m in modes],
        range=[MODE_META[m]["color"] for m in modes],
    )


def _summary(df: pd.DataFrame) -> pd.DataFrame:
    agg = (
        df.groupby("mode")
        .agg(
            runs=("total_ms", "count"),
            handshake_ms=("handshake_ms", "mean"),
            total_ms=("total_ms", "mean"),
            p95_total=("total_ms", lambda s: s.quantile(0.95)),
        )
        .reindex([m for m in MODE_ORDER if m in df["mode"].unique()])
        .reset_index()
    )
    agg["label"] = agg["mode"].map(_label)
    return agg


def render_dashboard() -> None:
    df = load_results()

    if df.empty:
        st.warning(
            "No benchmark data found. Generate it with:\n\n"
            "```bash\npython benchmarks/run_benchmarks.py --runs 30 "
            "--modes ml_kem hybrid --output benchmarks/results_all.csv\n```"
        )
        return

    summary = _summary(df)
    st.caption(
        f"Aggregated from **{len(df):,} timed handshakes** across "
        f"**{df['mode'].nunique()} key-exchange modes**. "
        "Every message is sealed with AES-256-GCM regardless of mode."
    )

    # ---- Headline KPI cards --------------------------------------------------
    by_mode = summary.set_index("mode")
    cols = st.columns(len(summary))
    for col, (_, row) in zip(cols, summary.iterrows()):
        meta = MODE_META[row["mode"]]
        tag = "🛡️ PQC-safe" if meta["pqc"] else "⚠️ Quantum-vulnerable"
        col.metric(
            label=f"{meta['label']} · {meta['sub']}",
            value=f"{row['handshake_ms']:,.1f} ms",
            help=f"Mean key-exchange time over {int(row['runs'])} runs",
        )
        col.caption(tag)

    # ---- The money number: speedup ------------------------------------------
    if "dh" in by_mode.index and "ml_kem" in by_mode.index:
        speedup = by_mode.loc["dh", "handshake_ms"] / by_mode.loc["ml_kem", "handshake_ms"]
        st.success(
            f"### ⚡ ML-KEM-768 completes its key exchange **{speedup:,.0f}× faster** "
            f"than classical 2048-bit Diffie–Hellman — while also being resistant to "
            f"Shor's algorithm on a quantum computer."
        )

    st.divider()

    # ---- Chart 1: handshake latency (log scale) -----------------------------
    st.subheader("Key-exchange latency by mode")
    st.caption("Log scale — classical DH is orders of magnitude slower, so a linear axis would flatten everything else.")
    hs = summary.copy()
    bar = (
        alt.Chart(hs)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
        .encode(
            x=alt.X("label:N", sort=[_label(m) for m in MODE_ORDER], title=None,
                    axis=alt.Axis(labelAngle=0)),
            y=alt.Y("handshake_ms:Q", scale=alt.Scale(type="log"),
                    title="Mean handshake (ms, log)"),
            color=alt.Color("label:N", scale=_color_scale(list(hs["mode"])), legend=None),
            tooltip=[
                alt.Tooltip("label:N", title="Mode"),
                alt.Tooltip("handshake_ms:Q", title="Handshake (ms)", format=",.2f"),
                alt.Tooltip("runs:Q", title="Runs"),
            ],
        )
        .properties(height=320)
    )
    text = bar.mark_text(dy=-8, color="#e2e8f0", fontSize=12).encode(
        text=alt.Text("handshake_ms:Q", format=",.1f")
    )
    st.altair_chart(bar + text, use_container_width=True)

    # ---- Chart 2: where the time goes (stacked breakdown) -------------------
    st.subheader("Where does the time go?")
    st.caption("Mean per-stage latency for the fast modes (DH excluded so the sub-millisecond detail is visible).")
    fast = df[df["mode"].isin(["ml_kem", "hybrid", "dh_cached"])]
    if not fast.empty:
        stage_mean = (
            fast.groupby("mode")[STAGE_COLS].mean().reset_index()
            .melt(id_vars="mode", var_name="stage", value_name="ms")
        )
        stage_mean["label"] = stage_mean["mode"].map(_label)
        stage_mean["stage_label"] = stage_mean["stage"].map(STAGE_LABELS)
        stacked = (
            alt.Chart(stage_mean)
            .mark_bar()
            .encode(
                x=alt.X("label:N", title=None, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("ms:Q", title="Mean latency (ms)"),
                color=alt.Color(
                    "stage_label:N",
                    title="Stage",
                    sort=list(STAGE_LABELS.values()),
                    scale=alt.Scale(range=["#38bdf8", "#8b5cf6", "#f472b6", "#22c55e"]),
                ),
                order=alt.Order("stage:N"),
                tooltip=[
                    alt.Tooltip("label:N", title="Mode"),
                    alt.Tooltip("stage_label:N", title="Stage"),
                    alt.Tooltip("ms:Q", title="ms", format=",.3f"),
                ],
            )
            .properties(height=320)
        )
        st.altair_chart(stacked, use_container_width=True)

    # ---- Chart 3: consistency (distribution) --------------------------------
    st.subheader("Consistency across runs")
    st.caption("Each dot is one full round-trip. Tight clusters = predictable latency.")
    dist_src = df[df["mode"] != "dh"] if df["mode"].nunique() > 1 else df
    strip = (
        alt.Chart(dist_src)
        .mark_circle(size=55, opacity=0.55)
        .encode(
            x=alt.X("total_ms:Q", title="Total round-trip (ms)"),
            y=alt.Y("mode:N", sort=[m for m in MODE_ORDER if m in dist_src["mode"].unique()],
                    title=None,
                    axis=alt.Axis(labelExpr="{'ml_kem':'ML-KEM-768','hybrid':'Hybrid','dh_cached':'DH cached'}[datum.value]")),
            color=alt.Color("mode:N",
                            scale=alt.Scale(domain=list(dist_src["mode"].unique()),
                                            range=[MODE_META[m]["color"] for m in dist_src["mode"].unique()]),
                            legend=None),
            tooltip=[alt.Tooltip("total_ms:Q", title="Total (ms)", format=",.2f"),
                     alt.Tooltip("run_id:Q", title="Run")],
        )
        .properties(height=220)
    )
    st.altair_chart(strip, use_container_width=True)

    # ---- Raw data ------------------------------------------------------------
    with st.expander("📄 Raw benchmark data & per-mode statistics"):
        st.dataframe(
            summary[["label", "runs", "handshake_ms", "total_ms", "p95_total"]]
            .rename(columns={
                "label": "Mode", "runs": "Runs",
                "handshake_ms": "Handshake (ms)", "total_ms": "Total avg (ms)",
                "p95_total": "Total p95 (ms)",
            })
            .style.format({"Handshake (ms)": "{:,.2f}", "Total avg (ms)": "{:,.2f}",
                           "Total p95 (ms)": "{:,.2f}"}),
            use_container_width=True, hide_index=True,
        )
        st.dataframe(df, use_container_width=True, hide_index=True, height=260)
