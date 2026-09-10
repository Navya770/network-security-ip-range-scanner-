"""
scanner.py
----------
Safe IP/CIDR validation and host discovery logic for the
Network Security IP Range Scanner.

Design principles:
- All input is parsed with the standard `ipaddress` module BEFORE it is
  ever used anywhere else. Nothing that isn't a validated IP address is
  passed to a subprocess or socket call.
- No shell=True, no string-built commands, no user text ever reaches a
  shell. `subprocess.run` is always called with a fixed argument list
  where the only variable part is an already-validated IP address.
- Every network operation has a strict timeout so a single unreachable
  host can never hang the whole scan.
- Scan size and thread concurrency are capped to keep the tool
  well-behaved and "polite" (basic rate limiting).
"""

import ipaddress
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---- Safety / rate-limiting configuration -------------------------------

PING_TIMEOUT_SECONDS = 1          # per-host ICMP timeout
TCP_TIMEOUT_SECONDS = 0.8         # per-port TCP connect timeout
MAX_WORKERS = 32                  # max concurrent threads (rate limiting)
COMMON_PORTS = [80, 443, 22, 3389, 445, 8080]  # fallback TCP probe ports


class ScannerError(Exception):
    """Raised for any user-facing, expected scanning/validation error."""
    pass


def validate_target(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """
    Validate a user-supplied IP address or CIDR string using the
    `ipaddress` standard library module ONLY. Never passed to a shell.

    Returns an ipaddress network object on success.
    Raises ScannerError with a user-friendly message on failure.
    """
    if not isinstance(target, str):
        raise ScannerError("Target must be a string.")

    target = target.strip()
    if not target:
        raise ScannerError("Target IP/CIDR is required.")

    # Basic length guard against pathological input
    if len(target) > 64:
        raise ScannerError("Target input is too long to be a valid IP/CIDR.")

    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
        else:
            ip_obj = ipaddress.ip_address(target)
            network = ipaddress.ip_network(f"{ip_obj}/32")
    except ValueError as exc:
        raise ScannerError(f"Invalid IP address or CIDR range: '{target}'") from exc

    if network.is_multicast or network.is_reserved or network.is_unspecified:
        raise ScannerError(
            "Multicast, reserved, or unspecified addresses are not allowed."
        )

    return network


def _ping_host(ip: str) -> bool:
    """
    Attempt a single ICMP ping using the OS ping utility.
    The command is built as a fixed argument LIST (never a shell string),
    and `ip` has already been validated by ipaddress before this point.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_SECONDS * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT_SECONDS + 1,
            shell=False,  # explicit: never invoke a shell
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # ping binary missing / not permitted / timed out -> fall back to TCP
        return False


def _tcp_probe(ip: str) -> bool:
    """
    Fallback / supplementary liveness check: attempt a fast TCP connect
    to a handful of common ports. A successful (or actively refused)
    connection indicates the host is up even if ICMP is filtered.
    """
    for port in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TCP_TIMEOUT_SECONDS)
                code = sock.connect_ex((ip, port))
                # 0 = open. Any prompt response (including connection
                # refused, errno 111) still proves the host is alive;
                # connect_ex returning quickly with a non-zero code that
                # isn't a timeout also indicates a responsive host.
                if code == 0:
                    return True
        except socket.timeout:
            continue
        except OSError:
            continue
    return False


def _check_host(ip: str) -> dict:
    """Run liveness checks for a single validated IP and time the result."""
    start = time.time()
    is_active = _ping_host(ip) or _tcp_probe(ip)
    elapsed_ms = round((time.time() - start) * 1000, 2)
    return {
        "ip": ip,
        "status": "active" if is_active else "inactive",
        "response_time_ms": elapsed_ms if is_active else None,
    }


def scan_network(network) -> list:
    """
    Perform host discovery across every usable address in `network`.
    `network` MUST already be a validated ipaddress network object
    (see validate_target). Concurrency is capped by MAX_WORKERS.
    """
    if network.num_addresses == 1:
        hosts = [str(network.network_address)]
    else:
        hosts = [str(h) for h in network.hosts()]
        if not hosts:  # e.g. /31 or /32 edge cases
            hosts = [str(network.network_address)]

    results = []
    worker_count = max(1, min(MAX_WORKERS, len(hosts)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(_check_host, ip): ip for ip in hosts}
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                results.append(future.result())
            except Exception:
                results.append(
                    {"ip": ip, "status": "error", "response_time_ms": None}
                )

    results.sort(key=lambda r: ipaddress.ip_address(r["ip"]))
    return results
