#!/usr/bin/env python3
"""
[41] Honeypot Creator
Author: Sahith
Language: Python 3 (Standard Library Only - Zero External Dependencies)

Description:
A lightweight, multi-threaded CLI Honeypot Creator that spins up configurable
decoy network services (SSH banner trap, HTTP Admin login portal, FTP banner trap,
and custom TCP listeners) on demand to capture reconnaissance probes, banners,
and unauthorized credential attempts.

Usage:
    python3 honeypot_creator.py --preset enterprise
    python3 honeypot_creator.py --ports 2121:FTP,2222:SSH,8080:HTTP
"""

import argparse
import json
import os
import socket
import sys
import threading
from datetime import datetime, timezone
from urllib.parse import parse_qs

LOG_FILE = "honeypot_captures.log"
_print_lock = threading.Lock()

PRESETS = {
    "enterprise": [
        {"port": 2121, "protocol": "FTP", "banner": "220 (vsFTPd 2.3.4)\r\n"},
        {"port": 2222, "protocol": "SSH", "banner": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"},
        {"port": 8080, "protocol": "HTTP", "banner": "Apache/2.4.29 (Ubuntu)"},
    ],
    "minimal": [
        {"port": 2222, "protocol": "SSH", "banner": "SSH-2.0-OpenSSH_8.2p1\r\n"},
        {"port": 8080, "protocol": "HTTP", "banner": "nginx/1.18.0"},
    ],
}


def log_capture(source_ip: str, source_port: int, target_port: int, protocol: str, event: str, data: str = ""):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    clean_data = data.replace("\r", "\\r").replace("\n", "\\n").strip()
    record = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "target_port": target_port,
        "protocol": protocol,
        "event": event,
        "payload": clean_data,
    }

    with _print_lock:
        print(
            f"[{timestamp}] [{protocol}:{target_port}] "
            f"{source_ip}:{source_port} -> {event} | {clean_data[:100]}"
        )
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def handle_http_client(conn: socket.socket, addr: tuple, target_port: int, server_banner: str):
    src_ip, src_port = addr
    try:
        conn.settimeout(5.0)
        raw_req = conn.recv(4096).decode("utf-8", errors="ignore")
        if not raw_req:
            return

        lines = raw_req.split("\r\n")
        request_line = lines[0] if lines else "UNKNOWN"
        parts = request_line.split(" ")
        method = parts[0] if len(parts) > 0 else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        if method == "POST" and "\r\n\r\n" in raw_req:
            body = raw_req.split("\r\n\r\n", 1)[1]
            parsed = parse_qs(body)
            user = parsed.get("username", [""])[0]
            pwd = parsed.get("password", [""])[0]
            log_capture(src_ip, src_port, target_port, "HTTP", f"LOGIN_ATTEMPT {path}", f"user={user} pass={pwd}")
            status_msg = "<p style='color:#ff6b6b;'>Invalid credentials. Incident logged.</p>"
        else:
            log_capture(src_ip, src_port, target_port, "HTTP", f"HTTP_PROBE {request_line}", "")
            status_msg = ""

        html_body = (
            "<!DOCTYPE html><html><head><title>Admin Gateway</title></head>"
            "<body style='font-family:monospace;background:#111;color:#eee;padding:40px;'>"
            "<h2>System Administration Login</h2>"
            f"{status_msg}"
            "<form method='POST' action='/login'>"
            "Username: <input name='username' required><br><br>"
            "Password: <input type='password' name='password' required><br><br>"
            "<button type='submit'>Login</button>"
            "</form></body></html>"
        )
        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Server: {server_banner}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(html_body.encode('utf-8'))}\r\n"
            "Connection: close\r\n\r\n"
            f"{html_body}"
        )
        conn.sendall(response.encode("utf-8"))
    except socket.timeout:
        log_capture(src_ip, src_port, target_port, "HTTP", "TIMEOUT_PROBE", "")
    except Exception as exc:
        log_capture(src_ip, src_port, target_port, "HTTP", "SOCKET_ERROR", str(exc))
    finally:
        conn.close()


def handle_generic_decoy(conn: socket.socket, addr: tuple, target_port: int, protocol: str, banner: str):
    src_ip, src_port = addr
    try:
        conn.settimeout(6.0)
        if banner:
            conn.sendall(banner.encode("utf-8", errors="ignore"))

        if protocol == "FTP":
            user_data = conn.recv(1024).decode("utf-8", errors="ignore")
            if user_data:
                log_capture(src_ip, src_port, target_port, protocol, "FTP_INPUT", user_data)
                conn.sendall(b"331 Please specify the password.\r\n")
                pass_data = conn.recv(1024).decode("utf-8", errors="ignore")
                if pass_data:
                    log_capture(src_ip, src_port, target_port, protocol, "FTP_PASS_ATTEMPT", pass_data)
                conn.sendall(b"530 Login incorrect.\r\n")
        else:
            client_data = conn.recv(2048)
            if client_data:
                hex_or_text = client_data.decode("utf-8", errors="replace")
                log_capture(src_ip, src_port, target_port, protocol, "CLIENT_PAYLOAD", hex_or_text)
            else:
                log_capture(src_ip, src_port, target_port, protocol, "BANNER_GRAB_ONLY", "")
    except socket.timeout:
        log_capture(src_ip, src_port, target_port, protocol, "CONNECTION_TIMEOUT", "")
    except Exception as exc:
        log_capture(src_ip, src_port, target_port, protocol, "CONNECTION_RESET", str(exc))
    finally:
        conn.close()


def start_listener(host: str, port: int, protocol: str, banner: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        sock.listen(50)
    except OSError as exc:
        print(f"[!] Failed to bind {host}:{port} ({protocol}): {exc}")
        return

    print(f"[+] Spawned {protocol:<6} decoy on {host}:{port}")
    while True:
        conn, addr = sock.accept()
        if protocol == "HTTP":
            t = threading.Thread(target=handle_http_client, args=(conn, addr, port, banner), daemon=True)
        else:
            t = threading.Thread(target=handle_generic_decoy, args=(conn, addr, port, protocol, banner), daemon=True)
        t.start()


def parse_custom_ports(port_spec: str) -> list:
    decoys = []
    default_banners = {
        "SSH": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
        "FTP": "220 (vsFTPd 2.3.4)\r\n",
        "TELNET": "\r\nUbuntu 20.04 LTS\r\nlogin: ",
        "HTTP": "Apache/2.4.29 (Ubuntu)",
        "TCP": "220 Service Ready\r\n",
    }
    for item in port_spec.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            p_str, proto = item.split(":", 1)
            proto = proto.upper()
        else:
            p_str, proto = item, "TCP"
        port = int(p_str)
        decoys.append({
            "port": port,
            "protocol": proto,
            "banner": default_banners.get(proto, "220 Ready\r\n"),
        })
    return decoys


def main():
    parser = argparse.ArgumentParser(
        description="[41] Honeypot Creator - Spawn multi-protocol network decoys on demand"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Interface IP to bind decoys on (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--preset",
        choices=list(PRESETS.keys()),
        default="enterprise",
        help="Built-in decoy preset profile (default: enterprise)",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Custom comma-separated port:protocol list (e.g., 2121:FTP,2222:SSH,8080:HTTP,2323:TELNET)",
    )
    args = parser.parse_args()

    decoys = parse_custom_ports(args.ports) if args.ports else PRESETS[args.preset]

    print("=" * 62)
    print(" [41] HONEYPOT CREATOR | Multi-Protocol Decoy Generator")
    print("=" * 62)

    for d in decoys:
        t = threading.Thread(
            target=start_listener,
            args=(args.host, d["port"], d["protocol"], d["banner"]),
            daemon=True,
        )
        t.start()

    print(f"[*] Logging all captured probes to: {os.path.abspath(LOG_FILE)}")
    print("[*] Press Ctrl+C to stop all decoys.\n")

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Honeypot Creator...")
        sys.exit(0)


if __name__ == "__main__":
    main()
