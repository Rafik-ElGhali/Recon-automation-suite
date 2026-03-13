import nmap

def nmap_scan(host, port_range="1-1024"):
    """
    Scans a host using Nmap with service/version detection.
    Returns a list of dicts for each open port found.
    """
    nm = nmap.PortScanner()
    results = []

    print(f"[*] Starting Nmap scan on {host} (ports {port_range})...")
    print(f"[*] This may take a minute...\n")

    try:
        nm.scan(hosts=host, ports=port_range, arguments="-sV")
    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        return results
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return results

    for scanned_host in nm.all_hosts():
        print(f"[*] Host : {scanned_host}")
        print(f"[*] State: {nm[scanned_host].state()}\n")

        for proto in nm[scanned_host].all_protocols():
            ports = nm[scanned_host][proto].keys()

            for port in sorted(ports):
                port_info = nm[scanned_host][proto][port]

                if port_info["state"] == "open":
                    entry = {
                        "port":    port,
                        "state":   port_info["state"],
                        "service": port_info["name"],
                        "version": f"{port_info['product']} {port_info['version']}".strip()
                    }
                    results.append(entry)

                    print(f"  [+] Port {port:>5}/{proto}  —  {entry['state']}")
                    print(f"           Service : {entry['service']}")
                    if entry["version"]:
                        print(f"           Version : {entry['version']}")

    return results


def main():
    host       = "scanme.nmap.org"
    port_range = "1-1024"

    results = nmap_scan(host, port_range)

    print(f"\n[*] Scan complete. {len(results)} open port(s) found.")


if __name__ == "__main__":
    main()