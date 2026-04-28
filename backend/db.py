"""
db.py — SQLite persistence layer for the secure chat backend.

WHY THIS EXISTS
---------------
The original server.py held all state in an in-memory Python Counter().
Any server restart wiped the entire vote tally. For a messaging system
this is unacceptable — delivered messages, user accounts, and session
tokens must survive restarts.

DESIGN: SINGLE WRITER THREAD
-----------------------------
SQLite does not handle concurrent writes from multiple threads safely
without causing "database is locked" errors. The naive fix — a threading
Lock around every write — works but produces scattered, fragile locking
code throughout the codebase.

Instead we use a single dedicated DB writer thread that owns ALL writes.
Other threads push write tasks onto a thread-safe queue.Queue. The writer
thread drains the queue sequentially. Reads can still happen from any
thread since SQLite allows concurrent reads (WAL mode).

SCHEMA
------
  users         — registered users with bcrypt hashed passwords
  sessions      — issued session tokens with expiry tracking
  messages      — persistent chat messages with delivery status
  seen_messages — replay protection: store seen message_ids with timestamp

Author: Aakarsh Prabhu
"""

import queue
import sqlite3
import threading
import time
from pathlib import Path


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

DB_FILE = Path("chat.db")
REPLAY_WINDOW_SECONDS = 300   # 5-minute window for replay detection


# ------------------------------------------------------------------
# Writer thread — the single owner of all DB writes
# ------------------------------------------------------------------

_write_queue: queue.Queue = queue.Queue()
_writer_thread: threading.Thread | None = None


def _writer_loop(db_path: Path) -> None:
    """
    Background thread that sequentially executes all write operations.
    Each task in the queue is a callable (lambda or function) that
    accepts a sqlite3.Connection and performs writes within a transaction.
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")   # enable WAL for concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row

    while True:
        task = _write_queue.get()
        if task is None:              # None is the shutdown sentinel
            break
        try:
            task(conn)
            conn.commit()
        except Exception as e:
            print(f"[DB] Write error: {e}")
            conn.rollback()
        finally:
            _write_queue.task_done()

    conn.close()


def start(db_path: Path = DB_FILE) -> None:
    """Initialise the DB schema and start the writer thread."""
    global _writer_thread

    # Run schema migration synchronously before handing off to the thread.
    _bootstrap_schema(db_path)

    _writer_thread = threading.Thread(
        target=_writer_loop,
        args=(db_path,),
        daemon=True,
        name="db-writer",
    )
    _writer_thread.start()


def stop() -> None:
    """Gracefully shut down the writer thread."""
    _write_queue.put(None)
    if _writer_thread:
        _writer_thread.join(timeout=5)


def _enqueue(task) -> None:
    """Push a write task onto the queue (non-blocking for callers)."""
    _write_queue.put(task)


# ------------------------------------------------------------------
# Schema bootstrap (runs once at startup, from the main thread)
# ------------------------------------------------------------------

def _bootstrap_schema(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            created_at    REAL    NOT NULL DEFAULT (unixepoch('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token         TEXT    PRIMARY KEY,
            username      TEXT    NOT NULL REFERENCES users(username),
            created_at    REAL    NOT NULL,
            expires_at    REAL    NOT NULL,
            invalidated   INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS messages (
            message_id      TEXT    PRIMARY KEY,
            sender          TEXT    NOT NULL,
            recipient       TEXT    NOT NULL,
            ciphertext_b64  TEXT,
            plaintext       TEXT,
            delivery_status TEXT    NOT NULL DEFAULT 'sent',
            created_at      REAL    NOT NULL,
            delivered_at    REAL,
            read_at         REAL
        );

        CREATE TABLE IF NOT EXISTS seen_messages (
            message_id  TEXT  PRIMARY KEY,
            received_at REAL  NOT NULL
        );
    """)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------
# Read helpers (called from any thread — safe under WAL mode)
# ------------------------------------------------------------------

def _read_conn(db_path: Path = DB_FILE) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def get_user(username: str, db_path: Path = DB_FILE) -> sqlite3.Row | None:
    with _read_conn(db_path) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def get_session(token: str, db_path: Path = DB_FILE) -> sqlite3.Row | None:
    with _read_conn(db_path) as conn:
        return conn.execute(
            "SELECT * FROM sessions WHERE token = ? AND invalidated = 0",
            (token,)
        ).fetchone()


def is_replay(message_id: str, db_path: Path = DB_FILE) -> bool:
    """Return True if this message_id has been seen before."""
    with _read_conn(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM seen_messages WHERE message_id = ?", (message_id,)
        ).fetchone()
    return row is not None


def get_pending_messages(recipient: str, db_path: Path = DB_FILE) -> list:
    """Return all messages queued for recipient that haven't been delivered."""
    with _read_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM messages WHERE recipient = ? AND delivery_status = 'sent' ORDER BY created_at",
            (recipient,)
        ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------
# Write helpers (enqueued — non-blocking)
# ------------------------------------------------------------------

def insert_user(username: str, password_hash: str) -> None:
    def task(conn):
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
    _enqueue(task)


def insert_session(token: str, username: str, expires_at: float) -> None:
    def task(conn):
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, username, time.time(), expires_at)
        )
    _enqueue(task)


def invalidate_session(token: str) -> None:
    def task(conn):
        conn.execute(
            "UPDATE sessions SET invalidated = 1 WHERE token = ?", (token,)
        )
    _enqueue(task)


def insert_message(message_id: str, sender: str, recipient: str,
                   plaintext: str, created_at: float) -> None:
    def task(conn):
        conn.execute(
            """INSERT INTO messages
               (message_id, sender, recipient, plaintext, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (message_id, sender, recipient, plaintext, created_at)
        )
    _enqueue(task)


def update_delivery_status(message_id: str, status: str) -> None:
    def task(conn):
        col = "delivered_at" if status == "delivered" else "read_at"
        conn.execute(
            f"UPDATE messages SET delivery_status = ?, {col} = ? WHERE message_id = ?",
            (status, time.time(), message_id)
        )
    _enqueue(task)


def record_seen(message_id: str) -> None:
    """Mark a message_id as seen (for replay protection)."""
    def task(conn):
        conn.execute(
            "INSERT OR IGNORE INTO seen_messages (message_id, received_at) VALUES (?, ?)",
            (message_id, time.time())
        )
    _enqueue(task)


def purge_old_seen(window_seconds: int = REPLAY_WINDOW_SECONDS) -> None:
    """Remove seen_messages older than the replay window (call periodically)."""
    cutoff = time.time() - window_seconds
    def task(conn):
        conn.execute(
            "DELETE FROM seen_messages WHERE received_at < ?", (cutoff,)
        )
    _enqueue(task)
