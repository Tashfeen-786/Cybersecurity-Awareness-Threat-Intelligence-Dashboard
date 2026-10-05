/**
 * API client for the Threat Intelligence Dashboard.
 *
 * Base-URL detection:
 *   - served by the FastAPI backend (port 8000 or https preview) -> relative
 *   - served by the separate static server (port 5500)          -> backend at 127.0.0.1:8000
 *   - opened as a local file (file://)                           -> backend at 127.0.0.1:8000
 */
(function () {
  const loc = window.location;
  let base;
  if (loc.protocol === "https:" || loc.port === "8000" || loc.port === "") {
    base = ""; // same origin (FastAPI serves the frontend)
  } else {
    base = "http://127.0.0.1:8000"; // separate static server
  }
  window.API_BASE = base;

  /** Fetch wrapper: adds the API key header, friendly error handling. */
  async function apiFetch(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    const key = sessionStorage.getItem("ti_api_key");
    if (key) headers["X-API-Key"] = key;
    let resp;
    try {
      resp = await fetch(base + "/api" + path, Object.assign({}, options, { headers }));
    } catch (err) {
      const e = new Error(
        "Cannot reach the backend API. Start it with scripts\\start_backend.bat " +
        "(or 'uvicorn app:app --port 8000' in backend/) and open " +
        (base || "http://127.0.0.1:8000") + " in your browser.");
      e.network = true;
      throw e;
    }
    if (resp.status === 401) {
      const e = new Error("Authentication required: sign in with an API key (top-right button).");
      e.status = 401;
      throw e;
    }
    if (resp.status === 403) {
      const e = new Error("Forbidden: your role does not have permission for this action.");
      e.status = 403;
      throw e;
    }
    if (resp.status === 429) {
      const body = await resp.json().catch(() => ({}));
      const e = new Error(body.detail || "Rate limit exceeded - please slow down.");
      e.status = 429;
      throw e;
    }
    if (!resp.ok) {
      let detail = resp.statusText;
      try {
        const body = await resp.json();
        if (typeof body.detail === "string") detail = body.detail;
        else if (body.detail && body.detail.message) detail = body.detail.message;
        else if (Array.isArray(body.detail)) detail = body.detail.map(d => (d.field || "") + ": " + (d.message || "")).join("; ");
      } catch (_) { /* keep statusText */ }
      const e = new Error("API error " + resp.status + ": " + detail);
      e.status = resp.status;
      throw e;
    }
    return resp.json();
  }

  window.api = {
    get: (p) => apiFetch(p),
    post: (p, body) => apiFetch(p, { method: "POST", body: JSON.stringify(body) }),
    put: (p, body) => apiFetch(p, { method: "PUT", body: JSON.stringify(body) }),
  };
})();
