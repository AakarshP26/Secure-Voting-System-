# Quantum-Secure Messaging Platform — User Guide

This guide provides a step-by-step walkthrough on how to run, use, and demonstrate the capabilities of the Secure Chat platform.

## 1. Prerequisites

You need Python 3.12 installed on your system.
Install the required dependencies if you haven't already:
```bash
pip install -r requirements.txt
```

Alternatively, if you have Docker installed, you can skip to **Section 4**.

## 2. Setting Up the Database

The platform uses a local SQLite database (`chat.db`) to store user credentials, offline messages, and delivery receipts.

Before starting the server, you need to register at least two users to test the chat functionality.
Run the following commands in your terminal:
```bash
python backend/register.py --user alice --password secret
python backend/register.py --user bob --password secret
```
*Note: You can use any usernames and passwords you like. The passwords are cryptographically hashed using `bcrypt` (work factor 12).*

## 3. Starting the Platform (Local Execution)

The platform consists of two parts: the **FastAPI Backend** and the **Streamlit Frontend**.

### Step 3a: Start the Backend Server
Open a terminal and run the backend using `uvicorn`:
```bash
uvicorn backend.server_async:app --host 127.0.0.1 --port 65432
```
You should see output indicating that the SQLite WAL database is ready and the server is listening. **Leave this terminal open.**

### Step 3b: Start the Streamlit Interface
Open a **second terminal** and run the frontend UI:
```bash
streamlit run frontend/app.py
```
This will automatically open a new tab in your default web browser pointing to `http://localhost:8501`.

---

## 4. Starting the Platform (Docker)

If you prefer to run the entire stack in an isolated container without dealing with multiple terminals, simply run:
```bash
docker build -t secure-chat .
docker run -p 8501:8501 -p 65432:65432 secure-chat
```
*Note: The Docker container automatically registers `alice` and `bob` for you during startup.*

Once the container is running, open your web browser and go to `http://localhost:8501`.

---

## 5. How to Use the Chat App

### 5.1 Logging In
1. On the Streamlit UI homepage, you will see a login screen.
2. Enter the username you registered (e.g., `alice`) and your password (e.g., `secret`).
3. Click **Login**.

### 5.2 The Crypto Inspector
On the right side of the screen, you will see the **Crypto Inspector** sidebar. 
Before sending a message, you must select the **Key Exchange Mode**. This determines how your browser securely exchanges a session key with the server:

* **`ml_kem`**: Uses the Post-Quantum FIPS 203 standard (ML-KEM-768). Fast and secure against future quantum computers, but relatively new.
* **`dh`**: Uses Classical Diffie-Hellman (RFC 7914). Proven, but theoretically vulnerable to Shor's Algorithm running on a future quantum computer.
* **`hybrid`**: Uses BOTH `ml_kem` and `dh`. The secrets are combined using HKDF-SHA256. This guarantees security as long as *at least one* of the underlying algorithms remains unbroken. **(Recommended)**

### 5.3 Sending Messages
1. In the main chat area, type the recipient's username in the **"To:"** field (e.g., `bob`). If you just want to test sending data to the server without a specific recipient, leave it as `server`.
2. Type your message in the text input box.
3. Click **Send**.

**What happens under the hood?**
When you click Send, the platform temporarily spins up an asynchronous WebSocket to the backend. It performs the cryptographic handshake you selected, authenticates using a secure session token, encrypts your message using **AES-256-GCM**, and fires it over the socket. The server decrypts it, saves it to the SQLite database, routes it to Bob's queue, and immediately sends an encrypted `delivered` ACK back to you.

### 5.4 Viewing Telemetry
Immediately after sending a message, look at the **Crypto Inspector** sidebar. It will update to show:
* **KEX Latency**: How many milliseconds the key exchange took. You will notice that `ml_kem` is astonishingly fast, often beating classical `dh`.
* **Total Latency**: The total time taken for the connection, handshake, authentication, encryption, payload delivery, and ACK receipt.
* **Bytes Sent / Recv**: The total wire overhead of your selected cryptographic algorithm. You will notice that `ml_kem` uses significantly larger payloads (~1KB public keys) compared to `dh`.

### 5.5 Two-Player Mode
To test bidirectional chat:
1. Open a **new Incognito Window** (or a different browser).
2. Navigate to `http://localhost:8501`.
3. Log in as `bob`.
4. Send a message to `alice`.
5. Go back to Alice's window and click **🔄 Check for new messages**.

Because the system uses SQLite persistence, even if Bob is offline when Alice messages him, the messages sit safely in his "offline queue". As soon as Bob logs in, his dashboard will fetch the history directly from the database.
