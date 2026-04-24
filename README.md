# Secure Voting System

A client-server voting system that demonstrates core cryptographic and network security
concepts: **Diffie-Hellman key exchange**, **AES-256 symmetric encryption**, and
**HMAC-SHA256** for message integrity.

Built as a coursework project for Network Programming & Security / Cryptography.

---

## Motivation

Real-world voting systems, messaging apps, and HTTPS all rely on the same fundamental
building blocks: a key exchange protocol to establish a shared secret, a symmetric cipher
to encrypt data efficiently, and a hash-based authentication code to detect tampering.

This project implements those building blocks from the ground up — wired into a
working client-server application — to demonstrate *why* each piece exists and *how*
they fit together.

---

## Features (Planned)

- [ ] TCP client-server architecture with concurrent voter support
- [ ] Diffie-Hellman key exchange to establish a shared session secret
- [ ] SHA-256 key derivation from the DH shared secret
- [ ] AES-256-CBC encryption of the vote payload
- [ ] HMAC-SHA256 integrity verification (Encrypt-then-MAC construction)
- [ ] Vote tally with per-session logging
- [ ] Unit tests for every cryptographic primitive

---

## Protocol Overview
CLIENT                                         SERVER
| --- TCP connect ----------------------------> |
| <-- DH params (p, g) + server public key A -- |
| --- client public key B -------------------->|
|                                               |
|       [both derive shared secret S]           |
|       [AES key K = SHA-256(S)]                |
|                                               |
| --- IV || ciphertext || HMAC_tag ----------> |
| <-- encrypted ACK -------------------------- |
Full protocol specification: see [`docs/protocol.md`](docs/protocol.md) *(coming soon)*.

---

## Tech Stack

- **Language:** Python 3.12
- **Cryptography:** [`cryptography`](https://cryptography.io/) library
- **Networking:** `socket` + `threading` (standard library)

---

## Project Status

🚧 **Under active development.** See commit history and branches for progress.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

Aakarsh Prabhu — [@AakarshP26](https://github.com/AakarshP26)