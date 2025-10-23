# Peer-to-Peer Secure Chat

A peer-to-peer encrypted chat program written in C with an OpenSSL backend and a Python (Tkinter) frontend.  
Messages are sent directly between peers with RSA key exchange and AES session encryption.

---

## Features
- End-to-end encrypted messaging (RSA + AES-GCM)
- Direct peer-to-peer communication (no server)
- Tkinter GUI for sending and receiving messages
- Works on Linux, macOS, and Windows (via WSL)
- Simple Makefile build system

---

## Build and Run

### 1. Clone the repository
'''bash
git clone https://github.com/mustafaryk/P2P-Secure-Chat-MK2.git
cd P2P-Secure-Chat-MK2

### 2. Compile the backend
'''bash
make

### 3. Run!
'''bash
python3 p2p.py

