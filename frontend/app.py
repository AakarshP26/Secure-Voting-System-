"""
app.py — Demo UI: chat + animated Network & Crypto packet flow.
"""
import streamlit as st
import sqlite3
import pandas as pd
import sys
import os
import asyncio
import socket
import threading
import time
import html

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.client_async import async_main
from dashboard import render_dashboard

st.set_page_config(
    page_title="Post-Quantum Secure Messaging",
    layout="wide",
    page_icon="🔐",
    initial_sidebar_state="collapsed",
)

DEMO_PEERS = {"alice": "bob", "bob": "alice"}

MODE_INFO = {
    "dh": "2048-bit DH",
    "ml_kem": "ML-KEM-768",
    "hybrid": "X25519 + ML-KEM-768",
}

FLOW_STAGES = [
    ("Compose", "Plaintext in browser", "plain"),
    ("Key exchange", "KEX → shared secret", "plain"),
    ("Derive AES key", "HKDF-SHA256 → session key", "plain"),
    ("Encrypt AUTH", "AES-GCM(password)", "cipher"),
    ("Login OK", "bcrypt verify → token", "cipher"),
    ("Encrypt message", "AES-GCM(JSON chat)", "cipher"),
    ("Uplink", "WebSocket → server :65432", "cipher"),
    ("Server route", "Decrypt · replay check · route/queue", "cipher"),
    ("Downlink ACK", "AES-GCM ACK ← server", "ack"),
    ("Done", "ACK verified · complete", "ack"),
]

UPLINK_POS = [5, 14, 24, 34, 44, 56, 72, 86, 90, 94]
RETURN_POS = [-1, -1, -1, -1, -1, -1, -1, -1, 38, 12]

if "user" not in st.session_state:
    st.session_state.user = None
    st.session_state.password = None
if "mode" not in st.session_state:
    st.session_state.mode = "hybrid"
if "metrics_log" not in st.session_state:
    st.session_state.metrics_log = []
if "send_error" not in st.session_state:
    st.session_state.send_error = None
if "last_recipient" not in st.session_state:
    st.session_state.last_recipient = "bob"
if "flow_stage" not in st.session_state:
    st.session_state.flow_stage = -1
if "flow_message" not in st.session_state:
    st.session_state.flow_message = ""


def fetch_messages(user: str) -> pd.DataFrame:
    try:
        db_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chat.db"
        )
        conn = sqlite3.connect(db_path)
        df = pd.read_sql(
            """
            SELECT sender, recipient, plaintext, created_at, delivery_status
            FROM messages WHERE sender = ? OR recipient = ?
            ORDER BY created_at ASC
            """,
            conn,
            params=(user, user),
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def backend_is_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 65432), timeout=2):
            return True
    except OSError:
        return False


def send_message(
    mode: str,
    user: str,
    password: str,
    message: str,
    recipient: str,
) -> tuple[dict | None, str | None]:
    """Run the WebSocket client (safe to call from a worker thread — no Streamlit)."""
    recipient = recipient.strip()

    if not backend_is_up():
        return None, (
            "Backend is not running on port 65432. "
            "Start: `.venv/bin/uvicorn backend.server_async:app --host 127.0.0.1 --port 65432`"
        )

    try:
        metrics = asyncio.run(
            async_main(mode, user, password, recipient, message, quiet=True)
        )
    except Exception as exc:
        return None, str(exc)

    if metrics is None:
        return None, "Authentication failed or server rejected the message. Use alice/secret or bob/secret."
    return metrics, None


def _esc(text: str) -> str:
    return html.escape(str(text)[:40])


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        .flow-wrap { font-family: system-ui, sans-serif; margin: 6px 0 12px 0; }
        .flow-title { font-size: 0.84rem; color: #94a3b8; margin-bottom: 6px; }
        .flow-track {
            position: relative; height: 84px;
            background: linear-gradient(90deg, #0f172a, #1e293b, #0f172a);
            border-radius: 12px; border: 1px solid #334155; overflow: hidden;
        }
        .flow-track.return {
            margin-top: 8px; height: 64px;
            background: linear-gradient(270deg, #0f172a, #14532d44, #0f172a);
        }
        .flow-node {
            position: absolute; top: 48px; transform: translateX(-50%);
            font-size: 0.67rem; color: #64748b; text-align: center; width: 68px;
        }
        .flow-node.on { color: #4ade80; font-weight: 700; }
        .flow-packet {
            position: absolute; top: 8px; transform: translateX(-50%);
            padding: 6px 11px; border-radius: 18px; font-size: 0.75rem;
            font-weight: 600; max-width: 148px; overflow: hidden;
            text-overflow: ellipsis; white-space: nowrap;
            transition: left 0.4s cubic-bezier(.4,0,.2,1);
            box-shadow: 0 4px 12px rgba(0,0,0,0.45); z-index: 2;
        }
        .flow-packet.plain { background: #2563eb; color: #fff; }
        .flow-packet.cipher { background: #7c3aed; color: #fff; }
        .flow-packet.ack { background: #16a34a; color: #fff; }
        .flow-packet.pulse { animation: pktpulse 0.48s ease-in-out; }
        @keyframes pktpulse { 50% { transform: translateX(-50%) scale(1.06); } }
        .flow-bar {
            position: absolute; bottom: 0; left: 0; height: 3px;
            background: linear-gradient(90deg, #3b82f6, #22c55e);
            transition: width 0.35s ease;
        }
        .crypto-lane {
            display: flex; flex-direction: column; gap: 4px;
            padding: 8px; background: #0f172a; border-radius: 12px;
            border: 1px solid #334155;
        }
        .crypto-step {
            display: flex; align-items: center; gap: 8px;
            padding: 6px 9px; border-radius: 8px;
            border: 1px solid #334155; background: #1e293b;
            font-size: 0.76rem; color: #64748b; transition: all 0.28s;
        }
        .crypto-step.on { border-color: #22c55e; background: #14532d66; color: #f8fafc; }
        .crypto-step.done { color: #94a3b8; }
        .crypto-payload {
            padding: 7px 10px; border-radius: 8px; margin-bottom: 6px;
            font-size: 0.71rem; font-family: ui-monospace, monospace;
        }
        .crypto-payload.plain { background: #1e3a5f; color: #93c5fd; }
        .crypto-payload.cipher { background: #3b0764; color: #e9d5ff; }
        .crypto-payload.ack { background: #14532d; color: #86efac; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _packet_label(msg: str, style: str) -> str:
    if style == "plain":
        return f"&quot;{_esc(msg)}&quot;"
    if style == "cipher":
        return f"🔒 enc({len(msg)} bytes)"
    return "✓ ACK"


def _network_html(stage: int, msg: str, user: str, peer: str) -> str:
    up = UPLINK_POS[min(stage, len(UPLINK_POS) - 1)]
    ret = RETURN_POS[min(stage, len(RETURN_POS) - 1)]
    pstyle = FLOW_STAGES[min(stage, len(FLOW_STAGES) - 1)][2]
    label = _packet_label(msg, pstyle)
    title = html.escape(FLOW_STAGES[min(stage, len(FLOW_STAGES) - 1)][0])
    bar = int(stage / (len(FLOW_STAGES) - 1) * 100)

    nodes = [(8, user, 0), (32, "KEX", 1), (55, "AES", 5), (74, ":65432", 6), (92, peer, 7)]
    nh = ""
    for pct, name, thresh in nodes:
        cls = "flow-node on" if stage >= thresh else "flow-node"
        nh += f'<div class="{cls}" style="left:{pct}%;">{_esc(name)}</div>'

    ret_pkt = ""
    if ret >= 0:
        ret_pkt = f'<div class="flow-packet ack pulse" style="left:{ret}%;">✓ ACK</div>'

    return f"""
    <div class="flow-wrap">
      <div class="flow-title">NETWORK — {title}</div>
      <div class="flow-track">
        {nh}
        <div class="flow-packet {pstyle} pulse" style="left:{up}%;">{label}</div>
        <div class="flow-bar" style="width:{bar}%;"></div>
      </div>
      <div class="flow-track return">
        <div class="flow-node" style="left:10%;">{_esc(user)}</div>
        <div class="flow-node" style="left:50%;">server</div>
        <div class="flow-node" style="left:90%;">{_esc(peer)}</div>
        {ret_pkt}
      </div>
    </div>
    """


def _crypto_html(stage: int, msg: str, mode: str) -> str:
    pstyle = FLOW_STAGES[min(stage, len(FLOW_STAGES) - 1)][2]
    if pstyle == "plain":
        payload = f'plaintext: "{_esc(msg)}"'
    elif pstyle == "cipher":
        payload = f"ciphertext: AES-GCM · {len(msg)} byte payload · mode={mode}"
    else:
        payload = "ACK decrypted · message_id matched · delivery confirmed"

    steps_html = ""
    for i, (name, detail, _) in enumerate(FLOW_STAGES):
        if i < stage:
            cls, icon = "crypto-step done", "✓"
        elif i == stage:
            cls, icon = "crypto-step on", "▶"
        else:
            cls, icon = "crypto-step", "○"
        steps_html += (
            f'<div class="{cls}"><span class="crypto-icon">{icon}</span>'
            f"<span><b>{html.escape(name)}</b> — {html.escape(detail)}</span></div>"
        )

    return f"""
    <div class="crypto-lane">
      <div style="font-size:0.84rem;color:#94a3b8;margin-bottom:4px;">
        CRYPTO — {html.escape(MODE_INFO.get(mode, mode))}
      </div>
      <div class="crypto-payload {pstyle}">{payload}</div>
      {steps_html}
    </div>
    """


def render_flow_panels(stage, msg, user, peer, mode, net_ph, crypto_ph):
    net_ph.markdown(_network_html(stage, msg, user, peer), unsafe_allow_html=True)
    crypto_ph.markdown(_crypto_html(stage, msg, mode), unsafe_allow_html=True)


def animate_and_send(
    message: str,
    recipient: str,
    user: str,
    peer: str,
    mode: str,
    password: str,
    net_ph,
    crypto_ph,
) -> tuple[dict | None, str | None]:
    send_result: dict = {"metrics": None, "error": None}

    def _worker() -> None:
        m, e = send_message(mode, user, password, message, recipient)
        send_result["metrics"] = m
        send_result["error"] = e

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    for s in range(len(FLOW_STAGES)):
        st.session_state.flow_stage = s
        st.session_state.flow_message = message
        render_flow_panels(s, message, user, peer, mode, net_ph, crypto_ph)
        time.sleep(0.35)

    thread.join(timeout=120)
    if thread.is_alive():
        return None, "Send timed out — use hybrid or ml_kem (dh is very slow)."
    return send_result["metrics"], send_result["error"]


_inject_styles()

if st.session_state.user is None:
    st.markdown(
        """
        <div style="text-align:center;padding:14px 0 2px 0;">
          <div style="font-size:2.4rem;font-weight:800;letter-spacing:-0.5px;">
            🔐 Post-Quantum Secure Messaging
          </div>
          <div style="color:#94a3b8;font-size:1.02rem;margin-top:4px;">
            A research testbed comparing classical vs. NIST post-quantum key exchange
            &nbsp;·&nbsp; ML-KEM-768 · X25519 · Diffie–Hellman · AES-256-GCM
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3)
    c1.markdown("##### 🛡️ Post-Quantum\nML-KEM-768 (FIPS 203) resists Shor's algorithm.")
    c2.markdown("##### 🔀 Hybrid\nX25519 + ML-KEM — today's industry best practice.")
    c3.markdown("##### 📊 Measured\nEvery handshake timed, benchmarked and charted.")

    st.divider()
    lc, rc = st.columns([1, 1])
    with lc:
        st.markdown("#### Enter the demo")
        st.markdown("**Accounts:** `alice` / `secret` · `bob` / `secret`")
        if backend_is_up():
            st.success("Backend online — ready to send")
        else:
            st.error("Backend offline — start it (see README) before sending")
        with st.form("login"):
            user = st.text_input("Username", value="alice")
            password = st.text_input("Password", type="password", value="secret")
            if st.form_submit_button("Enter demo", use_container_width=True):
                st.session_state.user = user.strip()
                st.session_state.password = password
                st.rerun()
    with rc:
        st.markdown("#### Why this matters")
        st.markdown(
            "**Store-now, decrypt-later (SNDL):** adversaries harvest encrypted "
            "traffic today to decrypt once quantum computers arrive. Classical key "
            "exchange (DH/RSA/ECDH) falls to **Shor's algorithm** — post-quantum "
            "KEMs like **ML-KEM** do not.\n\n"
            "Log in to watch a message travel the wire, then open the "
            "**📊 Benchmark Dashboard** to see the real performance cost of the migration."
        )
else:
    user = st.session_state.user
    peer_default = DEMO_PEERS.get(user, "bob")
    mode = st.session_state.mode
    stage = st.session_state.flow_stage
    flow_msg = st.session_state.flow_message

    h1, h2, h3 = st.columns([2, 1, 1])
    with h1:
        st.markdown(f"### 🔐 Post-Quantum Secure Messaging")
        st.caption(f"Signed in as **{user}**")
    with h2:
        st.session_state.mode = st.selectbox(
            "Key-exchange mode", ["hybrid", "ml_kem", "dh"],
            index=["hybrid", "ml_kem", "dh"].index(st.session_state.mode),
            help="hybrid = X25519 + ML-KEM-768 · ml_kem = pure PQC · dh = classical (slow)",
        )
        mode = st.session_state.mode
    with h3:
        if backend_is_up():
            st.success("Backend online")
        else:
            st.error("Backend offline")
        if st.button("Logout", use_container_width=True):
            st.session_state.user = None
            st.session_state.password = None
            st.session_state.flow_stage = -1
            st.rerun()

    tab_demo, tab_bench, tab_about = st.tabs(
        ["💬 Live Demo", "📊 Benchmark Dashboard", "🛡️ How It Works"]
    )

    with tab_demo:
        if st.session_state.send_error:
            st.error(st.session_state.send_error)
            st.session_state.send_error = None

        st.markdown("Watch your message move: **plaintext → encrypted → server → peer → ACK**")

        col_chat, col_net, col_crypto = st.columns([0.9, 1.2, 1.2])

        with col_net:
            st.subheader("Network")
            net_ph = st.empty()
        with col_crypto:
            st.subheader("Crypto")
            crypto_ph = st.empty()

        if stage >= 0 and flow_msg:
            render_flow_panels(stage, flow_msg, user, st.session_state.last_recipient, mode, net_ph, crypto_ph)
        else:
            net_ph.info("Uplink: you → :65432 → peer  ·  Downlink: ACK returns")
            crypto_ph.info("Steps light up as each crypto operation runs")

        with col_chat:
            st.markdown("#### Chat")
            df = fetch_messages(user)
            with st.container(height=260):
                if df.empty:
                    st.write("No messages yet.")
                else:
                    for _, row in df.iterrows():
                        mine = row["sender"] == user
                        with st.chat_message("user" if mine else "assistant"):
                            st.markdown(f"**{row['sender']}** → **{row['recipient']}**: {row['plaintext']}")
                            st.caption(row["delivery_status"])
            with st.form("chat_form", clear_on_submit=True):
                r1, r2, r3 = st.columns([1, 3, 1])
                recipient = r1.text_input("To", value=peer_default)
                message = r2.text_input("Message", placeholder="Hello…")
                go = r3.form_submit_button("Send")
                if go and message:
                    pw = st.session_state.password
                    metrics, err = animate_and_send(
                        message,
                        recipient,
                        user,
                        recipient.strip(),
                        mode,
                        pw,
                        net_ph,
                        crypto_ph,
                    )
                    if err:
                        st.session_state.send_error = err
                        st.session_state.flow_stage = -1
                    elif metrics:
                        metrics["recipient"] = recipient.strip()
                        metrics["sender"] = user
                        st.session_state.metrics_log.append(metrics)
                        st.session_state.last_recipient = recipient.strip()
                        st.session_state.flow_stage = len(FLOW_STAGES) - 1
                        st.session_state.flow_message = message
                    else:
                        st.session_state.send_error = "Send failed — check backend and credentials."
                    st.rerun()
            if st.button("Refresh"):
                st.rerun()

    with tab_bench:
        st.markdown("### 📊 Classical vs. Post-Quantum — measured")
        render_dashboard()

    with tab_about:
        st.markdown("### 🛡️ How It Works")
        st.markdown(
            "This testbed lets you switch the **key-exchange mode** in real time and "
            "observe the latency, bandwidth and security behaviour of each. "
            "Every message is sealed with **AES-256-GCM** no matter which mode is active."
        )
        a1, a2, a3 = st.columns(3)
        a1.markdown(
            "#### `dh`\n**2048-bit Diffie–Hellman**\n\n"
            "Classical key exchange. ⚠️ Broken by **Shor's algorithm** on a "
            "quantum computer. Regenerates fresh primes per connection → slow."
        )
        a2.markdown(
            "#### `ml_kem`\n**ML-KEM-768 (FIPS 203)**\n\n"
            "NIST's standardised post-quantum KEM (Kyber). 🛡️ Lattice-based, "
            "resistant to known quantum attacks, and millisecond-fast."
        )
        a3.markdown(
            "#### `hybrid`\n**X25519 + ML-KEM-768**\n\n"
            "Combines a classical and a post-quantum secret via HKDF-SHA256. "
            "🔀 Today's **industry best practice** — safe even if one primitive fails."
        )
        st.divider()
        st.markdown(
            "**Pipeline for every message**\n\n"
            "1. Key exchange → shared secret &nbsp; 2. HKDF-SHA256 → AES session key &nbsp; "
            "3. bcrypt auth → session token &nbsp; 4. AES-256-GCM encrypt &nbsp; "
            "5. WebSocket → server → replay check → route/queue &nbsp; 6. Encrypted ACK\n\n"
            "**Defences:** bcrypt password hashing · session tokens · "
            "`message_id` replay protection (5-minute window) · offline message queue."
        )
