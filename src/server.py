import socket
import threading

HOST = '127.0.0.1'


PORT = 65432



def handle_client(conn: socket.socket, addr: tuple) -> None:
    
    print(f"[+] New connection from {addr}")

    try:
       
        data = conn.recv(1024)

        if not data:
            print(f"[-] {addr} disconnected before sending data")
            return

       
        vote = data.decode('utf-8').strip()
        print(f"[VOTE RECEIVED] from {addr}: {vote!r}")

        conn.sendall(b"ACK: vote received")

    except ConnectionResetError:
        
        print(f"[-] Connection reset by {addr}")
    except Exception as e:
        
        print(f"[!] Error handling {addr}: {e}")
    finally:
       
        conn.close()
        print(f"[-] Connection closed with {addr}")


def start_server() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:

        
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_sock.bind((HOST, PORT))

        server_sock.listen(5)
        print(f"[SERVER] Listening on {HOST}:{PORT} ...")

        while True:
            conn, addr = server_sock.accept()

            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()
            print(f"[INFO] Active threads: {threading.active_count() - 1}")


if __name__ == '__main__':
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down (Ctrl+C pressed)")