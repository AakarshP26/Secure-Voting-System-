

import socket

HOST = '127.0.0.1'
PORT = 65432

def get_vote_from_user() -> str:
    candidates = {
        '1': 'Alice',
        '2': 'Bob',
        '3': 'Charlie',
    }

    print("\n=== BALLOT ===")
    for key, name in candidates.items():
        print(f"  [{key}] {name}")
    print("==============")

    while True:
        choice = input("Enter your vote (1/2/3): ").strip()
        if choice in candidates:
            return candidates[choice]
        print("Invalid choice, try again.")

def send_vote(vote: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
        print(f"[CLIENT] Connecting to {HOST}:{PORT} ...")
        client_sock.connect((HOST, PORT))
        print("[CLIENT] Connected.")
        client_sock.sendall(vote.encode('utf-8'))
        print(f"[CLIENT] Sent vote: {vote!r}")
        response = client_sock.recv(1024)
        print(f"[CLIENT] Server response: {response.decode('utf-8')}")

if __name__ == '__main__':
    try:
        vote = get_vote_from_user()
        send_vote(vote)
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to the server. Is it running?")
    except KeyboardInterrupt:
        print("\n[CLIENT] Cancelled.")