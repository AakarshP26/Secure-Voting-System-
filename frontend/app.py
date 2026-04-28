"""
app.py — Streamlit Frontend + Crypto Inspector Dashboard (Phase 5)

Provides a beautiful web UI for the secure chat platform.
Users can log in, select their cryptographic mode, and send messages.
The Crypto Inspector sidebar provides live telemetry on key exchange
latency, byte overhead, and security guarantees.
"""
import streamlit as st
import sqlite3
import pandas as pd
import sys
import os
import asyncio

# Ensure backend imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.client_async import async_main

st.set_page_config(page_title="Quantum-Secure Chat", layout="wide", page_icon="🔒")

# Initialize session state
if "user" not in st.session_state:
    st.session_state.user = None
    st.session_state.password = None
if "mode" not in st.session_state:
    st.session_state.mode = "hybrid"
if "metrics_log" not in st.session_state:
    st.session_state.metrics_log = []

def fetch_messages(user):
    """Read the plaintext messages from the backend's SQLite DB."""
    try:
        # Assumes chat.db is in the project root
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chat.db")
        conn = sqlite3.connect(db_path)
        query = """
            SELECT sender, recipient, plaintext, created_at, delivery_status 
            FROM messages 
            WHERE sender = ? OR recipient = ?
            ORDER BY created_at ASC
        """
        df = pd.read_sql(query, conn, params=(user, user))
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def run_client(message, recipient="server"):
    """Spawn the async client in single-message mode."""
    mode = st.session_state.mode
    user = st.session_state.user
    pw = st.session_state.password
    
    # We must patch asyncio if it complains about running loops
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    metrics = loop.run_until_complete(async_main(mode, user, pw, recipient, message, quiet=True))
    
    if metrics:
        st.session_state.metrics_log.append(metrics)

# ── LOGIN SCREEN ────────────────────────────────────────────────────────
if st.session_state.user is None:
    st.title("🔒 Quantum-Secure Messaging Platform")
    st.write("Log in to the E2E-encrypted chat environment.")
    
    with st.form("login"):
        user = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            st.session_state.user = user
            st.session_state.password = password
            st.rerun()

# ── MAIN APP SCREEN ─────────────────────────────────────────────────────
else:
    # Layout: Chat takes 2/3 of screen, Inspector takes 1/3
    col_chat, col_inspector = st.columns([2, 1])
    
    # ── CRYPTO INSPECTOR SIDEBAR ──
    with col_inspector:
        st.header("⚙️ Crypto Inspector")
        st.write("Live telemetry on the cryptographic pipeline.")
        
        st.session_state.mode = st.selectbox(
            "Key Exchange Mode",
            ["dh", "ml_kem", "hybrid"],
            index=["dh", "ml_kem", "hybrid"].index(st.session_state.mode),
            help="Select the cryptographic algorithm for the handshake."
        )
        
        if st.session_state.mode == "hybrid":
            st.success("Quantum-Safe + Classical Fallback")
        elif st.session_state.mode == "ml_kem":
            st.warning("Quantum-Safe (FIPS 203)")
        else:
            st.error("Classical Only (Vulnerable to Shor's Algorithm)")

        st.markdown("---")
        
        if st.session_state.metrics_log:
            latest = st.session_state.metrics_log[-1]
            st.subheader("Latest Message Telemetry")
            
            mc1, mc2 = st.columns(2)
            mc1.metric("KEX Latency", f"{latest['handshake_ms']:.1f} ms")
            mc2.metric("Total Latency", f"{latest['total_ms']:.1f} ms")
            
            mc3, mc4 = st.columns(2)
            mc3.metric("Bytes Sent", f"{latest['bytes_sent_app']} B")
            mc4.metric("Bytes Recv", f"{latest['bytes_received_app']} B")
            
            st.markdown("---")
            st.write("Recent history:")
            df_metrics = pd.DataFrame(st.session_state.metrics_log)
            # Display mode, latency, and size
            st.dataframe(df_metrics[["mode", "total_ms", "bytes_sent_app"]].tail(5), use_container_width=True)
        else:
            st.info("Send a message to populate telemetry.")
            
        st.markdown("---")
        if st.button("🚪 Logout"):
            st.session_state.user = None
            st.session_state.password = None
            st.rerun()

    # ── CHAT INTERFACE ──
    with col_chat:
        st.header(f"💬 Chat ({st.session_state.user})")
        
        # Display messages
        df = fetch_messages(st.session_state.user)
        
        # Chat history container
        chat_container = st.container(height=500)
        with chat_container:
            if df.empty:
                st.write("No messages yet.")
            else:
                for _, row in df.iterrows():
                    is_me = row['sender'] == st.session_state.user
                    name = "You" if is_me else row['sender']
                    # Use native Streamlit chat bubbles
                    with st.chat_message("user" if is_me else "assistant"):
                        st.markdown(f"**{name}** to **{row['recipient']}**: {row['plaintext']}")
                        # Small footer for delivery status
                        st.caption(f"Status: {row['delivery_status']}")

        # Input area
        with st.form("chat_form", clear_on_submit=True):
            cols = st.columns([1, 4, 1])
            recipient = cols[0].text_input("To:", value="server")
            message = cols[1].text_input("Message:", placeholder="Type a secure message...")
            submitted = cols[2].form_submit_button("Send")
            
            if submitted and message:
                with st.spinner("Encrypting and sending..."):
                    run_client(message, recipient)
                st.rerun()
                
        # Polling / Refresh button
        if st.button("🔄 Check for new messages"):
            st.rerun()
