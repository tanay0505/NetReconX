# 🔍 Network Reconnaissance Tool

A multi-threaded network reconnaissance tool built using Python that performs **ARP-based device discovery**, **OS fingerprinting**, **TCP & UDP port scanning** with **service detection** and **banner grabbing**.

<br>

## 🎬 Demo

![Demo](docs/demo.gif)

<br>

## 🧠 How It Works

![Architecture](docs/architecture.svg)

1. **Network Discovery (ARP)** — sends ARP requests to identify active devices, collects IP/MAC addresses
2. **OS Fingerprinting (TTL)** — sends ICMP ping, analyzes TTL to guess the OS with a confidence score
3. **TCP Port Scan** — threaded connect scan across a configurable port range
4. **UDP Port Scan** — protocol-specific probes (DNS, NTP, SNMP, NetBIOS) for accurate results
5. **Service Detection & Banner Grab** — maps ports to services, extracts banners, exports to JSON

<br>

## 🚀 Features

| Feature | Description |
|---|---|
| 🔎 Network discovery | ARP scan to find active devices and collect IP/MAC addresses |
| 🧬 OS fingerprinting | TTL-based detection (Linux / Windows / Network device / Solaris) with confidence scoring |
| 🌐 TCP scanning | Multi-threaded connect scan with configurable port range and thread count |
| 📶 UDP scanning | Protocol-specific probes for DNS, NTP, SNMP, NetBIOS + generic fallback |
| 🏷️ Service detection | Maps 25+ TCP/UDP ports to service names |
| 📡 Banner grabbing | Extracts service banners for deeper inspection |
| 📊 Progress tracking | Real-time tqdm progress bars for TCP and UDP scans |
| 📝 Logging | Full scan activity logged to `scanner.log` |
| 📄 JSON export | Structured output with targets, OS guesses, and open ports |
| 🔗 Flexible targeting | Single target or full network range |
| ✅ Unit tested | 17 tests covering core logic, no root required |

<br>

## 🛠️ Tech Stack

- Python 3
- Socket Programming
- `concurrent.futures.ThreadPoolExecutor`
- Scapy (ARP scanning, ICMP/UDP probes, OS fingerprinting)
- argparse (CLI interface)
- tqdm (progress bars)
- pytest (unit testing)
- logging

<br>

## ▶️ Usage

### Scan a single target (TCP, ports 20–1000, with OS fingerprinting)
```bash
sudo venv/bin/python main.py --target 192.168.1.1 --start 20 --end 1000
```

### Scan local network (ARP discovery + OS fingerprint + port scan)
```bash
sudo venv/bin/python main.py --network 192.168.1.0/24 --start 20 --end 1000
```

### Include UDP scanning
```bash
sudo venv/bin/python main.py --target 192.168.1.1 --udp
```

### Custom UDP ports + timeout
```bash
sudo venv/bin/python main.py --target 192.168.1.1 --udp --udp-ports 53,123,161,500 --udp-timeout 1.5
```

### Skip OS fingerprinting (faster scans)
```bash
sudo venv/bin/python main.py --target 192.168.1.1 --no-os-detect
```

### Tune thread count & timestamp output
```bash
sudo venv/bin/python main.py --target 192.168.1.1 --threads 200 --timestamp
```

<br>

### 🔧 CLI Flags

| Flag | Description | Default |
|---|---|---|
| `--target` | Single target IP or domain | — |
| `--network` | Network range for ARP scan (e.g. `192.168.1.0/24`) | — |
| `--start` / `--end` | TCP port range | `1` / `1000` |
| `--threads` | Max concurrent threads | `100` |
| `--udp` | Enable UDP scanning | off |
| `--udp-ports` | Comma-separated UDP ports | top 16 common ports |
| `--udp-timeout` | UDP probe timeout (seconds) | `2.0` |
| `--no-os-detect` | Skip OS fingerprinting | off |
| `--timestamp` | Add timestamp to output filename | off |

> **Note:** Root/sudo is required because the tool uses raw sockets (Scapy) for ARP scanning, OS fingerprinting, and UDP probes.

<br>

## 📄 Sample Output

```json
{
    "targets": [
        {
            "ip": "192.168.1.1",
            "mac": "10:10:81:e4:23:42",
            "os_guess": "Linux / Android",
            "ttl": 64,
            "os_confidence": "high"
        }
    ],
    "open_ports": [
        {
            "target": "192.168.1.1",
            "mac": "10:10:81:e4:23:42",
            "port": 80,
            "protocol": "tcp",
            "status": "open",
            "service": "HTTP",
            "banner": "HTTP/1.1 200 OK..."
        },
        {
            "target": "192.168.1.1",
            "port": 53,
            "protocol": "udp",
            "status": "open",
            "service": "DNS",
            "response": "DNS reply (answers=1)"
        }
    ]
}
```

<br>

## 📁 Output Files

- `results/<target>.json` → Scan results (targets + open ports)
- `scanner.log` → Logging information

<br>

## ✅ Running Tests

The core logic (service mapping, OS detection, port scanning) is unit-tested with mocked network calls — **no root or live network required**:

```bash
venv/bin/pip install pytest
venv/bin/python -m pytest tests/ -v
```

<br>

## 📦 Project Structure

```
.
├── main.py
├── scanner/
│   ├── core.py        # TCP connect scanning
│   ├── udp.py          # UDP scanning with protocol probes
│   ├── network.py      # ARP-based network discovery
│   ├── os_detect.py    # TTL-based OS fingerprinting
│   ├── banner.py        # Banner grabbing
│   ├── utils.py          # Service name mappings
│   └── logger.py         # Logging setup
├── tests/
│   └── test_scanner.py
├── docs/
│   ├── demo.gif
│   └── architecture.svg
├── results/             # JSON scan output (auto-created)
├── requirements.txt
└── README.md
```

<br>

## ⚠️ Disclaimer

This tool is intended for **educational and authorized testing purposes only**.
Do not use it on networks or systems without proper permission.
