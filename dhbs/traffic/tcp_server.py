import socket
import threading
import time

HOST, PORT = "0.0.0.0", 5000


def stamp():
    return time.strftime("%H:%M:%S")


def handle(conn):
    try:
        conn.sendall(b"HELLO from TCP server\n")
    except OSError:
        pass
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(256)
    print(f"[{stamp()}] TCP server listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        print(f"[{stamp()}] connection from {addr[0]}:{addr[1]}", flush=True)
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
