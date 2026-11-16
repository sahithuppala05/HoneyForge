# [41] Honeypot Creator — Python

A lightweight, **zero-dependency** Python 3 implementation of Project **[41] Honeypot creator** built in the exact single-script CLI style of `kurogai/100-redteam-projects`.

## How It Works
- **Pure Standard Library:** Uses only built-in `socket`, `threading`, `json`, and `argparse` modules—no external `pip install` required.
- **Dynamic Decoy Spawning:** Launch preset decoy clusters (`--preset enterprise`) or custom port/protocol combinations (`--ports 2121:FTP,2222:SSH,8080:HTTP,2323:TELNET`).
- **Interactive Traps:**
  - **HTTP Decoy:** Serves a fake System Administration Login portal and logs `GET` probes and `POST` credentials.
  - **FTP Decoy:** Simulates `vsFTPd 2.3.4`, accepts `USER` / `PASS` commands, and logs attempted credentials.
  - **SSH / TCP Decoys:** Advertises realistic service banners to catch `nmap -sV` scans and raw socket probes.
- **JSON Lines Telemetry:** Saves every connection event with UTC timestamps, source IP/port, and payload to `honeypot_captures.log`.

## Usage

### 1. Run with the default Enterprise Preset (FTP :2121, SSH :2222, HTTP :8080)
```bash
python3 honeypot_creator.py --preset enterprise
```

### 2. Create Custom Decoy Ports on Demand
```bash
python3 honeypot_creator.py --ports 2121:FTP,2222:SSH,2323:TELNET,8080:HTTP
```

### 3. Test Locally with Nmap / Netcat / Curl
```bash
nmap -sV -p 2121,2222,8080 127.0.0.1
curl -X POST http://127.0.0.1:8080/login -d "username=admin&password=Password123"
```
