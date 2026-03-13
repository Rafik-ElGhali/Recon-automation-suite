import socket

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    banner = ""

    try:
        result = sock.connect_ex((host, port))
        if result != 0:
            return False, ""

        sock.settimeout(0.5)

        if port == 80:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")

        try:
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            banner = ""

        return True, banner

    except socket.timeout:
        return False, ""
    except socket.error:
        return False, ""
    except Exception:
        return False, ""
    finally:
        sock.close()


def main():
    host = "scanme.nmap.org"
    port_range = range(20, 1025)

    print(f"[*] Resolving host: {host}")
    try:
        ip = socket.gethostbyname(host)
        print(f"[*] Target IP : {ip}")
    except socket.gaierror as e:
        print(f"[!] Could not resolve host: {e}")
        return

    print(f"[*] Scanning ports 20–1024 on {host}...\n")

    open_ports = []

    for port in port_range:
        is_open, banner = scan_port(ip, port)
        if is_open:
            open_ports.append(port)
            print(f"  [+] Port {port:>5} — OPEN")
            if banner:
                first_line = banner.splitlines()[0]
                print(f"           Banner : {first_line}")

    print(f"\n[*] Scan complete. {len(open_ports)} open port(s) found.")

if __name__ == "__main__":
    main()
