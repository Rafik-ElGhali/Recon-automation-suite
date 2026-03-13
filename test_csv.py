import csv
from datetime import datetime

rows = [
    {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host":    "scanme.nmap.org",
        "ip":      "45.33.32.156",
        "port":    22,
        "state":   "open",
        "service": "ssh",
        "banner":  "SSH-2.0-OpenSSH_6.6.1p1",
        "notes":   "Org: Linode"
    },
    {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host":    "scanme.nmap.org",
        "ip":      "45.33.32.156",
        "port":    80,
        "state":   "open",
        "service": "http",
        "banner":  "HTTP/1.1 200 OK",
        "notes":   "Org: Linode"
    }
]

fieldnames = ["timestamp", "host", "ip", "port", "state", "service", "banner", "notes"]

with open("test_results.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print("[*] CSV written to test_results.csv")
print(f"[*] {len(rows)} rows written.")