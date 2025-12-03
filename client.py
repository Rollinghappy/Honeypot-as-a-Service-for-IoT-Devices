import socket
import threading

BUFFER_SIZE = 65535


def log(msg):
    print(msg, flush=True)


def pipe(src, dst):
    """Pipe traffic bidirectionally."""
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass


def start_forwarder(local_ip, local_port, remote_ip, remote_port):
    """Listen locally and forward traffic to remote server."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((local_ip, local_port))
    listener.listen(50)

    log(f"[+] Forwarding {local_ip}:{local_port}  --->  {remote_ip}:{remote_port}")

    while True:
        client_sock, addr = listener.accept()
        log(f"[+] Incoming connection from {addr}")

        try:
            remote_sock = socket.create_connection((remote_ip, remote_port), timeout=10)
        except Exception as e:
            log(f"[!] Failed connecting to {remote_ip}:{remote_port} - {e}")
            client_sock.close()
            continue

        # Start bidirectional piping
        threading.Thread(target=pipe, args=(client_sock, remote_sock), daemon=True).start()
        threading.Thread(target=pipe, args=(remote_sock, client_sock), daemon=True).start()


def main():
    print("=== SIMPLE TCP PORT MAPPER ===")
    print("Maps ports from THIS machine to a REMOTE (public/global) server.\n")
    print("Example mapping format:")
    print("local_ip local_port remote_port")
    print("Example:")
    print("127.0.0.1 2222 22  (→ forwards localhost:2222 → SERVER:22)\n")

    remote_ip = input("Enter GLOBAL server IP: ").strip()
    if not remote_ip:
        print("Remote IP is required. Exiting.")
        return

    mappings = []

    while True:
        entry = input("\nEnter mapping or press Enter to finish: ").strip()
        if not entry:
            break

        parts = entry.split()
        if len(parts) != 3:
            print("Format must be: local_ip local_port remote_port")
            continue

        try:
            local_ip = parts[0]
            local_port = int(parts[1])
            remote_port = int(parts[2])
        except ValueError:
            print("Port numbers must be integers.")
            continue

        mappings.append((local_ip, local_port, remote_ip, remote_port))
        print(f"[+] Added: {local_ip}:{local_port} → {remote_ip}:{remote_port}")

    if not mappings:
        print("No mappings defined. Exiting.")
        return

    # Start threads
    print("\n[+] Starting all forwards...\n")

    for local_ip, local_port, r_ip, r_port in mappings:
        threading.Thread(
            target=start_forwarder,
            args=(local_ip, local_port, r_ip, r_port),
            daemon=True
        ).start()

    print("[+] All mappings active. Press Ctrl+C to stop.\n")

    # Keep alive
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        print("\n[+] Stopping.")


if __name__ == "__main__":
    main()

