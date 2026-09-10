"""
app.py
------
Flask backend for the Network Security IP Range Scanner.

Workflow:
    Frontend (fetch POST) -> /api/scan -> validate_target() ->
    scan_network() (host discovery) -> JSON results -> Frontend

Security notes:
- The only user-controlled value is the `target` string, which is
  validated exclusively via Python's `ipaddress` module before it is
  used anywhere else.
- Scan size is capped (MAX_HOSTS) to avoid excessive/unauthorized
  large-scale scanning and to keep response times reasonable.
- No shell commands are ever built from request data.
"""

from flask import Flask, render_template, request, jsonify

from scanner.scanner import validate_target, scan_network, ScannerError

app = Flask(__name__)

# Hard cap on how many hosts a single request may scan (basic rate limiting
# / abuse prevention). /24 = 254 usable hosts.
MAX_HOSTS = 256


@app.route("/")
def index():
    """Serve the single-page frontend."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Accepts JSON: {"target": "192.168.1.0/24"}
    Returns JSON: {
        "target": "...", "total_hosts": N, "active_hosts": N,
        "inactive_hosts": N,
        "results": [{"ip": "...", "status": "active|inactive", "response_time_ms": ...}, ...]
    }
    """
    if not request.is_json:
        return jsonify({"error": "Request body must be JSON."}), 400

    data = request.get_json(silent=True) or {}
    target = data.get("target", "")

    if not isinstance(target, str) or not target.strip():
        return jsonify({"error": "Target IP or CIDR range is required."}), 400

    # --- Validation ---
    try:
        network = validate_target(target)
    except ScannerError as exc:
        return jsonify({"error": str(exc)}), 400

    # --- Rate limiting / scope guard ---
    if network.num_addresses > MAX_HOSTS:
        return jsonify(
            {
                "error": (
                    f"Range too large ({network.num_addresses} addresses). "
                    f"Maximum allowed per scan is {MAX_HOSTS} hosts "
                    "(e.g. a /24 or smaller)."
                )
            }
        ), 400

    # --- Host discovery ---
    try:
        results = scan_network(network)
    except ScannerError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "An unexpected error occurred while scanning."}), 500

    active_count = sum(1 for r in results if r["status"] == "active")

    return jsonify(
        {
            "target": str(network),
            "total_hosts": len(results),
            "active_hosts": active_count,
            "inactive_hosts": len(results) - active_count,
            "results": results,
        }
    )


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"error": "Method not allowed."}), 405


@app.errorhandler(500)
def server_error(_error):
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    # debug=True is fine for local development only.
    app.run(debug=True, host="127.0.0.1", port=5000)
