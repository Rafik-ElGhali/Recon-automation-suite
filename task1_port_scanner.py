import socket

def scan_port(host, port):
    """
    Attempts a TCP connection to host:port.
    Returns True if the port is open, False otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except socket.timeout:
        return False
    except socket.error:
        return False
    except Exception:
        return False
    finally:
        sock.close()  # Always runs — even if an exception occurs


def main():
    host = "scanme.nmap.org"
    port_range = range(20, 1025)

    print(f"[*] Resolving host: {host}")
    try:
        ip = socket.gethostbyname(host)
        print(f"[*] Target IP: {ip}")
    except socket.gaierror as e:
        print(f"[!] Could not resolve host: {e}")
        return

    print(f"[*] Scanning ports 20–1024 on {host}...\n")

    open_ports = []

    for port in port_range:
        if scan_port(ip, port):
            open_ports.append(port)
            print(f"  [+] Port {port:>5} — OPEN")

    print(f"\n[*] Scan complete. {len(open_ports)} open port(s) found.")


if __name__ == "__main__":
    main()