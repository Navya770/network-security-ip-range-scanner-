# 🛡️ Network Security IP Range Scanner

A full-stack web application for discovering active/inactive hosts within
an IP address or CIDR range, built with a Flask backend and a vanilla
HTML/CSS/JS frontend.

> ⚠️ **Authorization Notice**
> This tool is intended **only** for scanning networks and IP ranges that
> you own or are explicitly authorized to test. Unauthorized scanning of
> third-party networks may be illegal in your jurisdiction and can
> violate acceptable-use policies of your ISP, employer, or cloud
> provider. By using this tool you confirm you have permission to scan
> the target range. The authorization warning is also displayed
> prominently in the web UI.

---

## 1. Objective

Provide a simple, safe, self-contained tool that lets an authorized user
enter an IP address or CIDR block and quickly see which hosts in that
range are currently active (reachable) and which are not — useful for
basic network inventory, authorized penetration-test recon, or teaching
the fundamentals of host discovery.

## 2. Features

- Enter a single IP (`192.168.1.10`) or a CIDR range (`192.168.1.0/24`)
- Strict backend-side IP/CIDR validation using Python's `ipaddress`
  module (no regex guessing, no shell involved)
- Host discovery performed entirely on the Flask backend:
  - Primary check: ICMP ping (OS ping utility, invoked safely)
  - Fallback check: TCP connect probe to common ports, used when ICMP
    is unavailable, blocked, or the environment lacks ping/raw-socket
    permissions (e.g. many containers)
- Active/Inactive status per host, with response time in ms
- Results table with IP address, status, and response time
- Loading/progress spinner while a scan is running
- Client- and server-side error handling with clear messages
- Safe timeouts on every host check + capped concurrency (basic rate
  limiting) so a scan can never hang indefinitely or hammer a network
- Hard cap on scan size (256 hosts / a `/24` or smaller) per request
- Prominent authorization warning banner in the UI
- **No arbitrary shell execution**: user input is never interpolated
  into a shell string; only validated IP addresses reach `subprocess`,
  and it is always called with a fixed argument list (`shell=False`)

## 3. Technologies Used

| Layer      | Technology                                |
|------------|--------------------------------------------|
| Frontend   | HTML5, CSS3, vanilla JavaScript (Fetch API) |
| Backend    | Python 3, Flask                             |
| Scanning   | Python `ipaddress`, `socket`, `subprocess`, `concurrent.futures` |
| Storage    | None — fully stateless, no database         |

## 4. Project Structure

```
netscan/
├── app.py                 # Flask application & API routes
├── requirements.txt       # Python dependencies
├── README.md
├── templates/
│   └── index.html         # Single-page frontend
├── static/
│   ├── style.css          # Styling
│   └── script.js          # Frontend logic (fetch, render, errors)
└── scanner/
    └── scanner.py          # IP validation + host discovery logic
```

## 5. Setup & Installation

### Prerequisites
- Python 3.9+ (uses only the standard library plus Flask)

### Steps

```bash
# 1. Clone / copy the project, then move into it
cd netscan

# 2. (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

The app will start at **http://127.0.0.1:5000**. Open that URL in your
browser.

> Note: ICMP ping may require elevated privileges on some operating
> systems, or may not be installed at all (common in minimal
> containers). The scanner automatically falls back to a TCP connect
> probe on common ports (80, 443, 22, 3389, 445, 8080) in that case, so
> the app works without root/administrator privileges.

## 6. How the Backend Works

**Workflow:**

```
Frontend (fetch POST /api/scan)
        │
        ▼
Flask route /api/scan (app.py)
        │
        ▼
validate_target()  → Python `ipaddress` module validates the string
        │              is a real IP/CIDR; rejects malformed input,
        │              multicast/reserved addresses, and oversized text
        ▼
Scope guard          → rejects ranges larger than MAX_HOSTS (256)
        │
        ▼
scan_network()       → expands the CIDR into individual host IPs and
        │               checks each one concurrently (thread pool,
        │               capped worker count)
        ▼
_check_host()  per IP → ICMP ping attempt (subprocess, fixed arg list,
        │                shell=False, strict timeout)
        │              → falls back to a TCP connect probe on common
        │                ports if ping is unavailable or fails
        ▼
JSON response         → { target, total_hosts, active_hosts,
                           inactive_hosts, results: [...] }
        │
        ▼
Frontend renders the results table + summary stats
```

### API

`POST /api/scan`

Request body:
```json
{ "target": "192.168.1.0/24" }
```

Success response (`200`):
```json
{
  "target": "192.168.1.0/24",
  "total_hosts": 254,
  "active_hosts": 3,
  "inactive_hosts": 251,
  "results": [
    { "ip": "192.168.1.1", "status": "active", "response_time_ms": 1.42 },
    { "ip": "192.168.1.2", "status": "inactive", "response_time_ms": null }
  ]
}
```

Error response (`400` / `500`):
```json
{ "error": "Invalid IP address or CIDR range: 'not-an-ip'" }
```

## 7. Testing

The application was tested locally end-to-end before delivery:

- **Unit-level checks** on `scanner.scanner`:
  - Valid CIDR/IP strings parse correctly
  - Malformed input (`999.999.999.999`) is rejected
  - Shell-injection-style strings (e.g. `127.0.0.1; rm -rf /`) are
    safely rejected by `ipaddress` and never reach a shell
  - Multicast/reserved addresses are rejected
  - A live TCP listener on `127.0.0.1` is correctly detected as
    `active`; a closed port on an unreachable address is correctly
    reported `inactive`
- **Flask test client** checks on every route:
  - `GET /` returns `200` and renders the page (including the
    authorization banner and scan form)
  - `POST /api/scan` with a missing/empty target → `400` with a clear
    error message
  - `POST /api/scan` with invalid or injection-style input → `400`,
    input never executed
  - `POST /api/scan` with a range larger than 256 hosts → `400`
  - `POST /api/scan` with a valid small range → `200` with a well-formed
    results payload
  - Non-JSON request body → `400`
  - Unknown route → `404` JSON error
- **Live HTTP smoke test**: ran `python app.py` and issued real
  `curl` requests against `/`, `/static/style.css`, `/static/script.js`,
  and `/api/scan` to confirm the whole stack serves correctly end to
  end.

To re-run the scanner unit checks yourself:

```bash
python3 -c "
from scanner.scanner import validate_target, scan_network
n = validate_target('127.0.0.1/30')
print(scan_network(n))
"
```

## 8. Security Considerations

- **No shell execution from user input.** The only external process
  invoked is the OS `ping` utility, called via `subprocess.run()` with
  a fixed list of arguments and `shell=False`. The only variable
  component is an IP address that has already been parsed and
  validated by Python's `ipaddress` module — it can never contain shell
  metacharacters that would be interpreted.
- **Strict input validation.** All target input is validated with
  `ipaddress.ip_address` / `ipaddress.ip_network` before any further
  processing. Invalid input is rejected with a clear error and never
  reaches the scanning layer.
- **Bounded scope.** A single scan is capped at 256 hosts to prevent
  accidental (or intentional) large-scale/unauthorized scanning and to
  keep response times reasonable.
- **Timeouts everywhere.** Every ping and TCP probe has a strict
  timeout, and the ping subprocess itself has a hard timeout, so a
  single unresponsive host can never hang the scan.
- **Concurrency capping.** Host checks run in a thread pool with a
  capped worker count, acting as basic rate limiting rather than
  flooding the target network with simultaneous probes.
- **No persistence.** No database or file storage is used — nothing
  scanned is written to disk, reducing data-handling risk.
- **User responsibility / authorization banner.** The UI displays a
  clear, persistent warning that the tool must only be used against
  networks the user owns or is authorized to test. This is a tool for
  legitimate network administration/security testing, not for
  unauthorized reconnaissance.
- **Debug mode.** `app.run(debug=True)` is intended for **local
  development only** — disable debug mode and use a production WSGI
  server (e.g. gunicorn/waitress) plus a reverse proxy before deploying
  anywhere beyond localhost.

## 9. Future Improvements

- Asynchronous/streaming scan progress (WebSocket or Server-Sent Events)
  instead of a single blocking request, with per-host progress updates
- Port scanning / service fingerprinting for discovered active hosts
- Export results to CSV/JSON/PDF
- Scan history (would require adding persistent storage)
- Configurable ping count, timeout, and port list from the UI
- IPv6 CIDR support in the UI (backend `ipaddress` already supports it)
- Pluggable authentication so the tool can be safely exposed beyond
  localhost, with per-user audit logging of what was scanned and by
  whom
- Optional integration with authorized scanning frameworks (e.g. Nmap)
  behind a strict, allow-listed, non-shell subprocess wrapper
