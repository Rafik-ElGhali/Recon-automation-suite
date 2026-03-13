# Recon Automation Suite

A Python-based network reconnaissance and scanning toolkit built to automate the core workflows of the active and passive recon phase in ethical hacking.

## Tools & Techniques

| Script | What it does |
|--------|-------------|
| `task1_port_scanner.py` | TCP port scanner using Python's `socket` library |
| `task2_banner_grabbing.py` | Banner grabbing — captures SSH, HTTP, FTP service banners |
| `task3_nmap_scanner.py` | Nmap integration via `python-nmap` for service/version detection |
| `task4_shodan_lookup.py` | Shodan OSINT lookup — passive recon without touching the target |
| `task5_final_scanner.py` | **Full combined scanner** — multi-threaded, CLI-driven, CSV + HTML output |

## Features

- Multi-threaded scanning with `concurrent.futures.ThreadPoolExecutor`
- Real-time progress bar via `tqdm`
- Service fingerprinting from banner keywords
- Optional Nmap `-sV` service/version detection
- Optional Shodan OSINT enrichment
- Structured CSV export (8 columns: timestamp, host, ip, port, state, service, banner, notes)
- Styled HTML report generation
- Full error handling — never crashes on network failures

## Requirements

```bash
pip install python-nmap shodan tqdm
```

Nmap must also be installed on your system:
- **Windows**: [nmap.org/download.html](https://nmap.org/download.html)
- **Linux/Mac**: `sudo apt install nmap` or `brew install nmap`

## Usage

```bash
# Default scan (scanme.nmap.org, ports 20-1024, 100 threads)
python task5_final_scanner.py

# With Nmap service detection
python task5_final_scanner.py --use-nmap

# With Shodan OSINT enrichment
python task5_final_scanner.py --shodan-key YOUR_KEY

# Custom target, port range, and thread count
python task5_final_scanner.py --host 192.168.1.1 --ports 1-65535 --threads 500 --output results
```

### All CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `scanme.nmap.org` | Target hostname or IP |
| `--ports` | `20-1024` | Port range (`20-1024`) or list (`22,80,443`) |
| `--threads` | `100` | Worker thread count |
| `--use-nmap` | off | Enable Nmap service/version detection |
| `--shodan-key` | — | Shodan API key for OSINT enrichment |
| `--output` | `scan_results` | Output filename base (no extension) |

### Shodan API Key

Set your key as an environment variable — never hardcode it:

```bash
# Windows
set SHODAN_API_KEY=your_key_here

# Linux / Mac
export SHODAN_API_KEY=your_key_here
```

## Output

- `scan_results.csv` — structured data for analysis, SIEM ingestion, or Excel
- `scan_results.html` — styled HTML report with summary statistics

## Ethical Notice

> Only scan systems you own or have explicit written permission to test.
> The default target `scanme.nmap.org` is publicly authorized for security testing by the Nmap team.
> Unauthorized port scanning may violate computer fraud laws in your jurisdiction.
