"""
task5_final_scanner.py

Final Lab: Combined Recon & Scanning Automation
Python for Cybersecurity -- Section 3

Integrates:
  - Socket-based port scanning with multi-threading
  - Banner grabbing & service detection
  - Nmap service/version detection (optional)
  - Shodan OSINT enrichment (optional)
  - CSV output
  - HTML report generation
  - CLI arguments via argparse
  - Progress bar via tqdm
"""

import socket
import csv
import html
import argparse
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


# ── Service fingerprinting ──────────────────────────────────────────────────

SERVICE_SIGNATURES = {
    "ssh":        ["SSH"],
    "ftp":        ["FTP", "FileZilla", "ProFTPD", "vsftpd"],
    "smtp":       ["SMTP", "ESMTP"],
    "pop3":       ["+OK", "POP3"],
    "imap":       ["IMAP", "* OK"],
    "http":       ["HTTP/", "Server:", "200 OK", "301 Moved", "403 Forbidden"],
    "mysql":      ["mysql", "MariaDB"],
    "rdp":        ["Remote Desktop"],
    "telnet":     ["login:"],
    "postgresql": ["PostgreSQL"],
}

WELL_KNOWN_PORTS = {
    21: "ftp",    22: "ssh",      23: "telnet",   25: "smtp",
    53: "dns",    80: "http",    110: "pop3",    143: "imap",
    443: "https", 445: "smb",   3306: "mysql",  3389: "rdp",
    5432: "postgresql",         8080: "http-alt",
}


def detect_service(port: int, banner: str) -> str:
    """Infer service name from banner keywords, then fall back to well-known ports."""
    b = banner.upper()
    for service, keywords in SERVICE_SIGNATURES.items():
        if any(kw.upper() in b for kw in keywords):
            return service
    return WELL_KNOWN_PORTS.get(port, "unknown")


# ── Core network functions ──────────────────────────────────────────────────

def resolve_host(hostname: str) -> str:
    """Resolve a hostname to an IP address. Raises RuntimeError on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        raise RuntimeError(f"Could not resolve '{hostname}': {e}")


def scan_port(host: str, port: int) -> tuple:
    """
    Attempt a TCP connection to host:port.
    Returns (is_open: bool, banner: str).
    Banner is captured via recv(); empty string if none received.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    banner = ""

    try:
        result = sock.connect_ex((host, port))
        if result != 0:
            return False, ""

        # Nudge HTTP ports to emit a response
        sock.settimeout(0.5)
        if port in (80, 8080, 8000, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")

        try:
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            pass

        return True, banner

    except (socket.timeout, socket.error, Exception):
        return False, ""
    finally:
        sock.close()


def nmap_scan(host: str, ports: str = "1-1024") -> list:
    """
    Run an Nmap service/version scan using python-nmap.
    Returns a list of dicts: {port, state, service, version}.
    Returns empty list if python-nmap or Nmap is unavailable.
    """
    if not NMAP_AVAILABLE:
        print("[!] python-nmap not installed -- skipping Nmap scan.")
        return []

    nm = nmap.PortScanner()
    results = []

    try:
        nm.scan(hosts=host, ports=ports, arguments="-sV --open")
    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        return []
    except Exception as e:
        print(f"[!] Nmap unexpected error: {e}")
        return []

    for scanned_host in nm.all_hosts():
        for proto in nm[scanned_host].all_protocols():
            for port in sorted(nm[scanned_host][proto].keys()):
                info = nm[scanned_host][proto][port]
                if info["state"] == "open":
                    results.append({
                        "port":    port,
                        "state":   info["state"],
                        "service": info["name"],
                        "version": f"{info['product']} {info['version']}".strip(),
                    })
    return results


def shodan_lookup(ip: str, api_key: str) -> dict:
    """
    Query Shodan for OSINT on an IP address.
    Returns a dict with org, os, country, ports, and banners.
    Returns None on error.
    """
    if not SHODAN_AVAILABLE:
        print("[!] shodan library not installed -- skipping Shodan lookup.")
        return None

    api = shodan.Shodan(api_key)
    try:
        result = api.host(ip)
        return {
            "ip":      result.get("ip_str", ip),
            "org":     result.get("org", "N/A"),
            "os":      result.get("os") or "N/A",
            "country": result.get("country_name", "N/A"),
            "ports":   result.get("ports", []),
            "banners": [
                {
                    "port":      s.get("port"),
                    "transport": s.get("transport", "tcp"),
                    "banner":    s.get("data", "").strip()[:200],
                }
                for s in result.get("data", [])
            ],
        }
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")
        return None
    except Exception as e:
        print(f"[!] Shodan unexpected error: {e}")
        return None


# ── Output functions ────────────────────────────────────────────────────────

CSV_FIELDS = ["timestamp", "host", "ip", "port", "state", "service", "banner", "notes"]


def save_to_csv(results: list, filename: str) -> None:
    """Write scan results to a CSV file using DictWriter."""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(results)
    print(f"[*] CSV saved  -> {filename}  ({len(results)} rows)")


def save_to_html(results: list, filename: str, host: str) -> None:
    """Generate a styled HTML report from scan results."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    open_count   = len(results)
    banner_count = sum(1 for r in results if r.get("banner"))
    services     = len({r["service"] for r in results if r["service"] != "unknown"})

    rows_html = ""
    for r in results:
        rows_html += (
            f"<tr>"
            f"<td>{html.escape(r['timestamp'])}</td>"
            f"<td>{html.escape(r['host'])}</td>"
            f"<td>{html.escape(r['ip'])}</td>"
            f"<td>{r['port']}</td>"
            f"<td class='s-open'>{r['state']}</td>"
            f"<td>{html.escape(r['service'])}</td>"
            f"<td class='banner'>{html.escape(r.get('banner',''))}</td>"
            f"<td>{html.escape(r.get('notes',''))}</td>"
            f"</tr>\n"
        )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scan Report -- {html.escape(host)}</title>
  <style>
    body  {{ font-family:'Segoe UI',Arial,sans-serif; background:#f4f6f9; color:#333; margin:0; padding:24px; }}
    h1    {{ color:#2E75B6; margin-bottom:4px; }}
    .meta {{ color:#666; margin-bottom:18px; font-size:13px; }}
    .summary {{ display:flex; gap:32px; background:#fff; border-radius:6px;
                padding:14px 20px; margin-bottom:20px;
                box-shadow:0 1px 4px rgba(0,0,0,.08); }}
    .stat-num   {{ font-size:26px; font-weight:bold; color:#2E75B6; }}
    .stat-label {{ font-size:11px; color:#888; }}
    table {{ width:100%; border-collapse:collapse; background:#fff;
             box-shadow:0 1px 4px rgba(0,0,0,.08); border-radius:4px; overflow:hidden; }}
    th    {{ background:#2E75B6; color:#fff; padding:10px 12px; text-align:left; font-size:13px; }}
    td    {{ padding:8px 12px; border-bottom:1px solid #e8e8e8; font-size:12px; }}
    tr:hover {{ background:#f0f7ff; }}
    .s-open  {{ color:#27ae60; font-weight:bold; }}
    .banner  {{ font-family:monospace; font-size:11px; word-break:break-all; max-width:280px; }}
  </style>
</head>
<body>
  <h1>Port Scan Report</h1>
  <div class="meta">Target: <strong>{html.escape(host)}</strong> &nbsp;|&nbsp; Generated: {ts}</div>
  <div class="summary">
    <div><div class="stat-num">{open_count}</div><div class="stat-label">Open Ports</div></div>
    <div><div class="stat-num">{services}</div><div class="stat-label">Unique Services</div></div>
    <div><div class="stat-num">{banner_count}</div><div class="stat-label">Banners Grabbed</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th><th>Host</th><th>IP</th><th>Port</th>
        <th>State</th><th>Service</th><th>Banner</th><th>Notes</th>
      </tr>
    </thead>
    <tbody>
{rows_html}    </tbody>
  </table>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"[*] HTML saved -> {filename}")


# ── Orchestrator ────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    """Print helper that works alongside tqdm."""
    if TQDM_AVAILABLE:
        tqdm.write(msg)
    else:
        print(msg)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lab 4 -- Recon & Scanning Automation (Python for Cybersecurity)"
    )
    parser.add_argument("--host",       default="scanme.nmap.org",
                        help="Target hostname or IP  (default: scanme.nmap.org)")
    parser.add_argument("--ports",      default="20-1024",
                        help="Port range or list  (default: 20-1024)")
    parser.add_argument("--threads",    default=100, type=int,
                        help="Worker threads  (default: 100)")
    parser.add_argument("--shodan-key", default="",
                        help="Shodan API key for OSINT enrichment")
    parser.add_argument("--use-nmap",   action="store_true",
                        help="Run Nmap service detection after socket scan")
    parser.add_argument("--output",     default="scan_results",
                        help="Output filename base without extension  (default: scan_results)")
    args = parser.parse_args()

    # Parse port list
    try:
        if "-" in args.ports:
            lo, hi = args.ports.split("-", 1)
            port_list = list(range(int(lo), int(hi) + 1))
        else:
            port_list = [int(p) for p in args.ports.split(",")]
    except ValueError:
        print("[!] Invalid --ports value. Use range (20-1024) or list (22,80,443).")
        return

    print(f"\n{'='*58}")
    print(f"  Lab 4 -- Recon & Scanning Automation")
    print(f"{'='*58}")
    print(f"  Target   : {args.host}")
    print(f"  Ports    : {args.ports}  ({len(port_list)} total)")
    print(f"  Threads  : {args.threads}")
    print(f"  Nmap     : {'enabled' if args.use_nmap  else 'disabled'}")
    print(f"  Shodan   : {'enabled' if args.shodan_key else 'disabled'}")
    print(f"  Output   : {args.output}.csv / {args.output}.html")
    print(f"{'='*58}\n")

    # 1. Resolve hostname
    print(f"[*] Resolving {args.host} ...")
    try:
        ip = resolve_host(args.host)
        print(f"[*] IP address : {ip}\n")
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 2. Shodan OSINT (passive -- before touching the target)
    shodan_data = None
    if args.shodan_key:
        print(f"[*] Querying Shodan for {ip} ...")
        shodan_data = shodan_lookup(ip, args.shodan_key)
        if shodan_data:
            print(f"    Org     : {shodan_data['org']}")
            print(f"    OS      : {shodan_data['os']}")
            print(f"    Country : {shodan_data['country']}")
            shodan_ports_str = ", ".join(str(p) for p in sorted(shodan_data["ports"]))
            print(f"    Ports   : {shodan_ports_str}\n")

    # 3. Nmap scan (optional)
    nmap_index = {}
    if args.use_nmap:
        print(f"[*] Running Nmap -sV scan (may take a moment) ...")
        nmap_results = nmap_scan(ip, args.ports)
        nmap_index   = {r["port"]: r for r in nmap_results}
        print(f"[*] Nmap found {len(nmap_index)} open port(s).\n")

    # 4. Threaded socket scan
    print(f"[*] Socket scan: {len(port_list)} ports, {args.threads} threads ...\n")
    open_ports = {}  # {port: banner}

    def _worker(port):
        return port, *scan_port(ip, port)

    progress = tqdm(total=len(port_list), unit="port", ncols=72, colour="blue") \
               if TQDM_AVAILABLE else None

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(_worker, p): p for p in port_list}
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if progress:
                progress.update(1)
            if is_open:
                open_ports[port] = banner
                service    = detect_service(port, banner)
                first_line = banner.splitlines()[0] if banner else ""
                _log(f"  [+] Port {port:>5}  --  OPEN  [{service}]")
                if first_line:
                    _log(f"           {first_line}")

    if progress:
        progress.close()

    print(f"\n[*] Socket scan complete: {len(open_ports)} open port(s) found.\n")

    # 5. Build result rows
    results = []
    for port in sorted(open_ports.keys()):
        banner  = open_ports[port]
        service = detect_service(port, banner)

        # Prefer Nmap service name if available
        if port in nmap_index:
            nmap_service = nmap_index[port].get("service", "")
            if nmap_service:
                service = nmap_service

        # Notes from Shodan
        notes = ""
        if shodan_data:
            notes = f"Org: {shodan_data['org']} | OS: {shodan_data['os']}"
            for b in shodan_data.get("banners", []):
                if b["port"] == port and not banner:
                    banner = b["banner"]
                    break

        results.append({
            "timestamp": timestamp,
            "host":      args.host,
            "ip":        ip,
            "port":      port,
            "state":     "open",
            "service":   service,
            "banner":    banner.splitlines()[0] if banner else "",
            "notes":     notes,
        })

    # 6. Save outputs
    if results:
        save_to_csv(results,  f"{args.output}.csv")
        save_to_html(results, f"{args.output}.html", args.host)
    else:
        print("[*] No open ports found -- nothing to save.")

    print(f"\n[*] Done.\n")


if __name__ == "__main__":
    main()
