// script.js
// Handles the scan form: sends the target to the Flask backend,
// shows a loading indicator, and renders results / errors.

(function () {
  const form = document.getElementById("scan-form");
  const targetInput = document.getElementById("target");
  const scanBtn = document.getElementById("scan-btn");
  const loading = document.getElementById("loading");
  const loadingText = document.getElementById("loading-text");
  const errorBox = document.getElementById("error-box");
  const resultsCard = document.getElementById("results-card");
  const summary = document.getElementById("summary");
  const resultsBody = document.getElementById("results-body");

  function showLoading(show) {
    loading.classList.toggle("hidden", !show);
    scanBtn.disabled = show;
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
  }

  function clearError() {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
  }

  function clearResults() {
    resultsCard.classList.add("hidden");
    summary.innerHTML = "";
    resultsBody.innerHTML = "";
  }

  function renderResults(data) {
    summary.innerHTML = `
      <div class="stat"><strong>${data.target}</strong>Target</div>
      <div class="stat"><strong>${data.total_hosts}</strong>Total Hosts</div>
      <div class="stat"><strong>${data.active_hosts}</strong>Active</div>
      <div class="stat"><strong>${data.inactive_hosts}</strong>Inactive</div>
    `;

    resultsBody.innerHTML = "";
    data.results.forEach((row) => {
      const tr = document.createElement("tr");

      const ipTd = document.createElement("td");
      ipTd.textContent = row.ip;

      const statusTd = document.createElement("td");
      const pill = document.createElement("span");
      const statusClass =
        row.status === "active"
          ? "active"
          : row.status === "inactive"
          ? "inactive"
          : "error";
      pill.className = `status-pill ${statusClass}`;
      pill.innerHTML = `<span class="status-dot"></span>${row.status}`;
      statusTd.appendChild(pill);

      const timeTd = document.createElement("td");
      timeTd.textContent =
        row.response_time_ms !== null && row.response_time_ms !== undefined
          ? `${row.response_time_ms} ms`
          : "—";

      tr.appendChild(ipTd);
      tr.appendChild(statusTd);
      tr.appendChild(timeTd);
      resultsBody.appendChild(tr);
    });

    resultsCard.classList.remove("hidden");
  }

  async function runScan(target) {
    const controller = new AbortController();
    // Client-side safety net timeout (backend also enforces its own
    // per-host timeouts); prevents a hung fetch from blocking the UI.
    const timeoutId = setTimeout(() => controller.abort(), 60000);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
        signal: controller.signal,
      });

      let payload;
      try {
        payload = await response.json();
      } catch (parseErr) {
        throw new Error("Received an unexpected response from the server.");
      }

      if (!response.ok) {
        throw new Error(payload.error || `Scan failed (HTTP ${response.status}).`);
      }

      return payload;
    } catch (err) {
      if (err.name === "AbortError") {
        throw new Error("The scan timed out. Try a smaller range.");
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();
    clearResults();

    const target = targetInput.value.trim();
    if (!target) {
      showError("Please enter an IP address or CIDR range.");
      return;
    }

    loadingText.textContent = `Scanning ${target}, please wait…`;
    showLoading(true);

    try {
      const data = await runScan(target);
      renderResults(data);
    } catch (err) {
      showError(err.message || "Something went wrong while scanning.");
    } finally {
      showLoading(false);
    }
  });
})();
