# Post-Quantum Secure Messaging Testbed

A production-inspired, transport-encrypted messaging platform built to **measure, compare, and visualize the performance tradeoffs** of migrating from classical cryptography (Diffie-Hellman) to NIST Post-Quantum standards (ML-KEM / FIPS 203).

> **Positioning**: This is a *research testbed*, not a production chat application. Its value lies in the empirical data it produces and the architectural decisions it demonstrates.

---

## 📌 The Problem

"Store-now, decrypt-later" (SNDL) attacks are a known threat model in which adversaries harvest today's encrypted traffic and plan to decrypt it once cryptographically relevant quantum computers (CRQCs) become available. Classical key exchange algorithms (DH, RSA, ECDH) are vulnerable to Shor's Algorithm running on such hardware.

NIST finalized ML-KEM (Kyber) as the first Post-Quantum Key Encapsulation Mechanism standard (FIPS 203) in 2024. The practical question this project answers is: **what does the migration actually cost in a real system?**

---

## 🚀 What This Project Does

This platform lets you **switch between three cryptographic key exchange modes in real time** and observe the latency, bandwidth, and security behavior of each:

| Mode | Algorithm | Status |
| :--- | :--- | :--- |
| `dh` | Classical 2048-bit Diffie-Hellman | Quantum-vulnerable |
| `ml_kem` | NIST ML-KEM-768 (FIPS 203) | Post-Quantum |
| `hybrid` | X25519 + ML-KEM-768 via HKDF-SHA256 | Industry Best Practice |

Every message is encrypted with **AES-256-GCM** regardless of which key exchange mode is selected.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│           Streamlit Frontend             │
│  (Chat UI + Live Crypto Inspector)      │
└────────────────┬────────────────────────┘
                 │  WebSocket
┌────────────────▼────────────────────────┐
│         FastAPI Backend (Async)          │
│  ┌──────────────┐  ┌──────────────────┐ │
│  │  WebSocket   │  │  Sync Crypto     │ │
│  │  Event Loop  │◄─│  (via Adapter)   │ │
│  └──────────────┘  └──────────────────┘ │
│  ┌──────────────────────────────────────┐│
│  │  SQLite (WAL)  │  Message Router    ││
│  │  Auth + Queue  │  Replay Protection ││
│  └──────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

**Key design decisions:**
- **Adapter Pattern**: Synchronous, thread-safe `WebSocketAdapter` bridges the blocking crypto layer to the async FastAPI event loop without rewriting any cryptographic primitives.
- **Single-Writer DB**: All writes route through a dedicated thread to avoid SQLite lock contention.
- **Server-Trusted Model**: The server decrypts messages for routing. This is *not* a zero-knowledge or client-side-only E2EE design.

---

## ⚙️ Key Features

- **Three switchable key exchange modes** with live telemetry
- **AES-256-GCM** payload encryption on every message
- **bcrypt password hashing** for user authentication
- **Session tokens** issued post-authentication
- **Replay protection** via `message_id` deduplication with a 5-minute sliding window
- **Offline message queue**: messages to offline users are stored in SQLite and drained immediately on their next login
- **Streamlit Crypto Inspector**: animated packet-flow view of every message (plaintext → encrypted → server → peer → ACK)
- **Interactive Benchmark Dashboard**: in-app Altair charts comparing classical vs. post-quantum latency, live from the CSV data (log-scale handshake comparison, per-stage breakdown, run-to-run consistency)
- **Automated benchmark harness**: 100+ runs per mode, CSV output, matplotlib plots
- **Replay attack simulator**: programmatic proof of tamper resistance

---

## 📊 Benchmark Results

Collected from 100+ automated iterations (50× ML-KEM, 50× Hybrid, 5× DH).

| Mode | Avg. Handshake | Avg. Total | App-Layer Bytes |
| :--- | ---: | ---: | ---: |
| **DH (Classical)** | 14,714.9 ms | 14,947.9 ms | 354.8 B |
| **ML-KEM (PQC)** | **5.2 ms** | 229.5 ms | 359.5 B |
| **Hybrid** | 19.9 ms | 243.4 ms | 359.4 B |

> **Why is DH so slow?** Each connection generates fresh 2048-bit prime parameters, measuring the worst-case CPU cost. ML-KEM uses lattice-based math (matrix multiplication), which modern CPUs execute in milliseconds.
>
> **Why does Hybrid add only ~14ms?** It runs X25519 + ML-KEM sequentially, but both are computationally lightweight. The overhead is negligible for any real-time use case.
>
> ⚠️ **Telemetry note**: App-layer bytes capture message metadata. Raw handshake wire bytes (ML-KEM public keys ≈ 2.5 KB vs. DH ≈ 256 B) are not fully tracked in the current telemetry. This is a known limitation.

![Benchmark Results](docs/benchmark_results.png)

---

## 🔒 Security Validation

**Replay Attack Test** — confirmed working:

```
[*] Connecting to ws://127.0.0.1:65432/ws/hybrid ...
[+] Authentication successful.
[*] Sending original message (ID: 6e83091af04c...)
[*] Attempting REPLAY attack with same payload...
[+] Server accepted: sent          ← original
[+] Server rejected: message_id 6e83091af04c... already seen  ← replay blocked
```

The server maintains a `seen_messages` table and rejects any message whose ID has already been processed within the 5-minute window.

---

## 🛠️ Setup & Running

### A. Manual Setup (Local Python)

**Requirements**: Python 3.12+

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Register demo users
python backend/register.py --user alice --password secret
python backend/register.py --user bob   --password secret

# 3. Start backend (keep this terminal open)
uvicorn backend.server_async:app --host 127.0.0.1 --port 65432

# 4. Start frontend (new terminal)
streamlit run frontend/app.py
```

Open `http://localhost:8501` in your browser.

### B. Docker Setup (Recommended for Demo)

```bash
# Build
docker build -t secure-chat .

# Run (seeds alice + bob automatically)
docker run -p 8501:8501 -p 65432:65432 secure-chat
```

Open `http://localhost:8501`. Credentials: `alice` / `secret` and `bob` / `secret`.

---

## 🎮 Usage / Demo Guide

1. **Login** at `http://localhost:8501` as `alice` (password: `secret`).
2. On the **💬 Live Demo** tab, **select a Key Exchange Mode** from the dropdown (`dh`, `ml_kem`, `hybrid`).
3. **Send a message** to `bob`. Watch the animated **Network** and **Crypto** panels light up as each stage runs.
4. Open the **📊 Benchmark Dashboard** tab to see the classical-vs-post-quantum performance gap rendered as interactive charts (ML-KEM is ~45,000× faster than fresh-parameter DH).
5. Open the **🛡️ How It Works** tab for a plain-English breakdown of the three modes and the message pipeline.
6. **Open an Incognito window**, log in as `bob` — offline messages arrive instantly from the queue.

---

## 📈 Running Benchmarks

```bash
# Run 50 iterations of PQC modes (fast, ~3 minutes)
python benchmarks/run_benchmarks.py --runs 50 --modes ml_kem hybrid --output benchmarks/results_pqc.csv

# Run 6 iterations of DH (slow, ~10+ minutes per run)
python benchmarks/run_benchmarks.py --runs 6 --modes dh --output benchmarks/results_dh.csv

# Generate comparison graph
python benchmarks/plot_results.py
# → saves to docs/benchmark_results.png
```

**What each metric means:**

| Metric | Meaning |
| :--- | :--- |
| `handshake_ms` | Time for key exchange math only |
| `total_ms` | Full round-trip: connect → auth → send → ACK |
| `bytes_sent_app` | Application-layer payload bytes sent |

---

## 🛡️ Security Simulation

```bash
# Ensure the server is running first, then:
python benchmarks/simulate_replay.py
```

This script authenticates as `alice`, sends a valid message, then immediately replays the same encrypted packet. The server's replay protection rejects the duplicate and logs the rejection.

---

## ✅ Project Status

**~92% complete** as a research testbed.

| Component | Status |
| :--- | :--- |
| Backend (FastAPI + WebSocket) | ✅ Complete |
| Crypto layer (DH / ML-KEM / Hybrid / AES) | ✅ Complete |
| Auth + bcrypt + session tokens | ✅ Complete |
| Replay protection | ✅ Complete |
| Offline message queue | ✅ Complete |
| Streamlit UI + Crypto Inspector | ✅ Complete |
| Benchmark harness + CSV output | ✅ Complete |
| Matplotlib result graphs | ✅ Complete |
| Replay attack simulation | ✅ Complete |
| Docker deployment | ✅ Complete |
| Unit tests (27 passing) | ✅ Complete |
| Full handshake bandwidth telemetry | 🔲 Partial |
| E2EE / Client-side decryption | 🔲 Not implemented |
| Horizontal scalability | 🔲 Not implemented |
| Research paper draft | 🔲 Not started |

---

## 🚧 Limitations (Honest)

- **Not production scalable**: SQLite is a single-writer database. It cannot support multiple concurrent server nodes.
- **Server-Trusted architecture**: The server decrypts messages for routing. A true E2EE system would not decrypt at the server.
- **Incomplete bandwidth telemetry**: Handshake-phase public key bytes (ML-KEM ≈ 2.5 KB per connection) are not yet captured in the CSV output. Only application-layer bytes are tracked.
- **DH benchmark reflects worst-case**: Fresh prime generation per connection is intentional (worst-case measurement), but DH with cached parameters would be significantly faster.
- **Not a Signal/WhatsApp replacement**: This is a controlled testbed for cryptographic evaluation, not a deployable consumer product.

---

## 🔭 Future Work

1. **Full bandwidth telemetry**: Instrument the adapter layer to count raw handshake bytes, producing a complete apples-to-apples bandwidth comparison.
2. **Research paper**: Formalise the results into an IEEE/ACM-style paper documenting the performance characteristics of ML-KEM in real-time messaging systems.
3. **E2EE extension**: Implement a double-ratchet or similar client-side key derivation to eliminate the server-trusted requirement.
4. **Scalability**: Replace SQLite with PostgreSQL and introduce a stateless session model for horizontal scaling.
5. **ML-KEM-1024**: Benchmark the higher-security parameter set and compare against ML-KEM-768.

---

## 🎯 Who This Project Is For

- **Students** learning applied cryptography and system design.
- **Engineers** evaluating the practical cost of migrating from classical to post-quantum key exchange.
- **Interviewers / Evaluators** who want to see measured, evidence-backed reasoning about cryptographic systems.
- **Researchers** looking for an open, reproducible PQC testbed.

---

## 🧪 Tests

```bash
pytest tests/ -v
# 27 tests covering AES, DH, ML-KEM, Hybrid, and KDF primitives — all passing.
```

---

## 📁 Repository Structure

```
├── backend/               Core server + crypto logic
│   ├── server_async.py    FastAPI WebSocket server
│   ├── client_async.py    Async WebSocket client
│   ├── client.py          Sync crypto client (via adapter)
│   ├── adapter.py         WebSocketAdapter (sync↔async bridge)
│   ├── protocol.py        JSON message schema + validation
│   ├── db.py              SQLite persistence layer
│   ├── auth.py            bcrypt auth + session tokens
│   ├── router.py          In-memory connection routing
│   ├── register.py        CLI user registration tool
│   └── crypto/
│       ├── aes.py         AES-256-GCM encrypt/decrypt
│       ├── dh.py          2048-bit Diffie-Hellman
│       ├── ml_kem.py      ML-KEM-768 (pqcrypto wrapper)
│       ├── hybrid.py      X25519 + ML-KEM combiner
│       ├── kdf.py         HKDF-SHA256 key derivation
│       └── kex_handlers.py Pluggable handler interface
├── benchmarks/
│   ├── run_benchmarks.py  Automated harness (subprocess-based)
│   ├── plot_results.py    Matplotlib graph generator
│   └── simulate_replay.py Replay attack demonstration
├── frontend/
│   └── app.py             Streamlit UI + Crypto Inspector
├── tests/                 27 unit tests for crypto primitives
├── docs/
│   └── benchmark_results.png  Pre-generated comparison graph
├── Dockerfile             Single-container full-stack deployment
└── requirements.txt
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE).