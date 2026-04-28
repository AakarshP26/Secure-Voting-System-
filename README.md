# Quantum-Secure Messaging & PQC Evaluation Platform

[![Tests](https://img.shields.io/badge/tests-27%20passed-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.12-blue)]()
[![Status](https://img.shields.io/badge/build-phase%202%20complete-orange)]()
[![Security](https://img.shields.io/badge/crypto-ML--KEM--768%20%2B%20X25519-red)]()

> A post-quantum secure messaging backend and cryptography evaluation platform.  
> Implements NIST FIPS 203 ML-KEM-768, Hybrid X25519+ML-KEM, and Classical DH —  
> with live benchmarking, structured authentication, and replay protection.

---

## 🚦 Current Build Status

| Phase | Status | Description |
|---|---|---|
| **Phase 0** | ✅ Complete | Repository restructure — `backend/` scaffold, imports fixed |
| **Phase 1** | ✅ Complete | JSON protocol layer — structured payloads, schema validation |
| **Phase 2** | ✅ Complete | SQLite persistence, bcrypt auth, session tokens, replay protection |
| **Phase 3** | ✅ Complete | Message router, ACK system, offline queue, interactive client |
| **Phase 4** | ✅ Complete | FastAPI + WebSocket migration (asyncio) |
| **Phase 5** | ✅ Complete | Streamlit frontend + Crypto Inspector dashboard |
| **Phase 6** | ✅ Complete | Docker + deployment |

---

## Docker Deployment (Recommended)
You can run the entire platform (backend, frontend, database) with a single command:
```bash
docker build -t secure-chat .
docker run -p 8501:8501 -p 65432:65432 secure-chat
```
The container automatically provisions two demo users (`alice` and `bob`, password: `secret`). Navigate to `http://localhost:8501` to view the app!

---

## What this project is

This is **not** a new cryptographic algorithm. It is a **system-level evaluation platform** that:

1. Implements three key exchange modes on identical infrastructure (DH, ML-KEM-768, Hybrid X25519+ML-KEM)
2. Runs them under realistic chat workloads with authentication, message routing, and replay protection
3. Measures and compares handshake latency, wire size, and security guarantees side-by-side
4. Simulates attacks (replay, tampering) to demonstrate why each layer of security exists

> Correct framing: *"A post-quantum secure messaging platform and PQC evaluation system that makes the transition from classical to post-quantum cryptography concrete and measurable."*

---

## Architecture

```
backend/
├── server.py          # TCP server — key exchange → auth → message routing
├── client.py          # TCP client — connects, authenticates, sends messages
├── register.py        # CLI tool — register users in the database
├── protocol.py        # JSON schema — message types, builders, validators
├── auth.py            # bcrypt password hashing, session token lifecycle
├── db.py              # SQLite + single writer thread, WAL mode
├── crypto/
│   ├── ml_kem.py      # ML-KEM-768 (FIPS 203) — post-quantum KEM
│   ├── hybrid.py      # Hybrid X25519 + ML-KEM combiner (IETF draft)
│   ├── dh.py          # Classical 2048-bit Diffie-Hellman
│   ├── aes.py         # AES-256-GCM authenticated encryption
│   ├── kdf.py         # HKDF-SHA256 key derivation
│   └── kex_handlers.py # Strategy pattern — pluggable key exchange
└── utils/
    └── protocol.py    # TCP framing — 4-byte length-prefixed messages

src/                   # Original prototype (preserved, tests still pass)
tests/                 # 27 unit tests — all green
benchmarks/            # Automated harness, CSV output, matplotlib figures
```

---

## Security model

| Layer | Implementation | Status |
|---|---|---|
| Key Exchange | Hybrid X25519 + ML-KEM-768 | ✅ |
| Symmetric Encryption | AES-256-GCM | ✅ |
| Key Derivation | HKDF-SHA256 | ✅ |
| Password Storage | bcrypt (rounds=12) | ✅ |
| Session Tokens | 256-bit random hex, 60-min expiry | ✅ |
| Replay Protection | message_id dedup + 5-min timestamp window | ✅ |
| Message Persistence | SQLite WAL, single writer thread | ✅ |
| E2EE | ❌ Server-trusted model (E2EE is a defined future phase) |

---

## Quickstart

```bash
# Install dependencies
pip install -r requirements.txt

# Register a user
python backend/register.py --user alice --password secret

# Start the FastAPI server (supports dh, ml_kem, hybrid routes)
uvicorn backend.server_async:app --host 127.0.0.1 --port 65432

# Send a message via WebSocket (in a second terminal)
python backend/client_async.py --mode hybrid --user alice --password secret --message "Hello"

# Or enter interactive REPL mode by omitting --message
python backend/client_async.py --mode hybrid --user alice --password secret

# Or start the Streamlit UI (recommended)
streamlit run frontend/app.py

# Run unit tests
pytest tests/ -v
```

---

## Benchmarks

The existing benchmarking suite in `benchmarks/` measures handshake latency across all modes.

| Mode | Median Handshake | Public Key Size | Quantum-Safe |
|---|---|---|---|
| DH (fresh params) | ~30,000 ms | ~256 B | ❌ |
| DH (cached params) | ~5 ms | ~256 B | ❌ |
| ML-KEM-768 | ~5 ms | 1,184 B | ✅ |
| Hybrid X25519+ML-KEM | ~5 ms | 1,216 B | ✅ |

---

## Author

Aakarsh Prabhu — [@AakarshP26](https://github.com/AakarshP26)