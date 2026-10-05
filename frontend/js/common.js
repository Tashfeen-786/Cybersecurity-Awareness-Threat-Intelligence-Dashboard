/**
 * Shared UI helpers: navbar, badges, escaping, loading states, auth dialog.
 *
 * SECURITY: every dynamic value is rendered with textContent / escapeHtml.
 * The dashboard never uses innerHTML with unescaped API/user data (XSS
 * defence-in-depth on top of backend sanitization).
 */
(function () {
  // ---------------- HTML escaping (XSS protection) -------------------------
  window.escapeHtml = function (value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  };

  window.fmtDate = function (iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (isNaN(d)) return String(iso).slice(0, 10);
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  };
  window.fmtDateTime = function (iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (isNaN(d)) return String(iso);
    return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  };

  window.sevBadge = (s) => `<span class="badge sev-${escapeHtml(s)}">${escapeHtml(s)}</span>`;
  window.statusBadge = (s) => `<span class="badge st-${escapeHtml(s)}">${escapeHtml(s).replace(/_/g, " ")}</span>`;
  window.typeBadge = (t) => `<span class="badge type">${escapeHtml(t)}</span>`;
  window.catBadge = (c) => `<span class="badge cat">${escapeHtml(c)}</span>`;

  window.riskColor = (score) =>
    score >= 81 ? "#ef4444" : score >= 61 ? "#f97316" : score >= 41 ? "#eab308" : score >= 21 ? "#22c55e" : "#64748b";
  window.confColor = (score) =>
    score >= 81 ? "#22c55e" : score >= 61 ? "#84cc16" : score >= 41 ? "#eab308" : "#ef4444";

  window.riskPill = function (score) {
    if (score === null || score === undefined) return "—";
    return `<span class="risk-pill"><span class="bar"><i style="width:${Math.max(3, score)}%;background:${riskColor(score)}"></i></span>${score}</span>`;
  };

  // ---------------- Loading / error helpers -------------------------------
  window.showLoading = (el, msg = "Loading data from local backend…") => {
    el.innerHTML = `<div class="loading"><div class="spinner"></div><div>${escapeHtml(msg)}</div></div>`;
  };
  window.showError = (el, err) => {
    el.innerHTML = `<div class="error-box"><strong>⚠ Could not load data.</strong><br>${escapeHtml(err && err.message ? err.message : err)}</div>`;
  };

  // ---------------- Navbar -------------------------------------------------
  const NAV_ITEMS = [
    ["index.html", "Home", "home-nav"],
    ["threat-dashboard.html", "Threat Dashboard", "dashboard-nav"],
    ["ioc_search.html", "IOC Search", "ioc-nav"],
    ["alerts.html", "Alerts", "alerts-nav"],
    ["vulnerabilities.html", "Vulnerabilities", "vuln-nav"],
    ["mitre_attack.html", "MITRE ATT&CK", "attack-nav"],
    ["awareness.html", "Awareness Center", "awareness-nav"],
    ["quiz.html", "Security Quiz", "quiz-nav"],
    ["executive_summary.html", "Executive View", "exec-nav"],
    ["soc_workflow.html", "SOC Workflow", "soc-nav"],
  ];

  window.renderNavbar = function () {
    const current = window.location.pathname.split("/").pop() || "index.html";
    const links = NAV_ITEMS.map(([href, label]) =>
      `<a href="${href}" class="${current === href ? "active" : ""}">${label}</a>`).join("");
    const bar = document.createElement("div");
    bar.className = "synth-banner";
    bar.innerHTML = "<span class='dot'>◆</span> SYNTHETIC / DEMO ONLY — all indicators are fictional, generated for defensive cybersecurity education. No real threat data.";
    const nav = document.createElement("nav");
    nav.className = "navbar";
    nav.innerHTML = `
      <div class="nav-inner">
        <a class="brand" href="index.html" style="text-decoration:none">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" fill="#22d3ee" opacity=".18"/>
            <path d="M12 2L4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" stroke="#22d3ee" stroke-width="1.6"/>
            <path d="M9 12l2 2 4-4.5" stroke="#22d3ee" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          <span>Cyber Threat Intel<span class="sub">AWARENESS &amp; THREAT INTELLIGENCE DASHBOARD</span></span>
        </a>
        <div class="nav-links">${links}</div>
        <div class="nav-right">
          <span class="key-badge" id="key-badge" onclick="openKeyDialog()" title="Sign in with an API key (demo keys in .env.example)">🔑 Sign in (API key)</span>
        </div>
      </div>`;
    document.body.prepend(nav);
    document.body.prepend(bar);
    refreshKeyBadge();
  };

  // ---------------- API-key sign-in (authentication demo) -------------------
  window.openKeyDialog = function () {
    const existing = document.getElementById("key-modal");
    if (existing) { existing.classList.remove("hidden"); return; }
    const modal = document.createElement("div");
    modal.id = "key-modal";
    modal.className = "modal-backdrop";
    modal.innerHTML = `
      <div class="modal">
        <h3>🔑 Sign in — API key (RBAC demo)</h3>
        <p class="modal-sub">Analyst functions (notes, status changes, threat creation) require an
        authenticated API key. Demo keys are documented in <span class="mono">.env.example</span>.
        Keys are stored only in your browser session, sent as the <span class="mono">X-API-Key</span> header,
        and never logged.</p>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <input type="text" id="key-input" placeholder="Paste API key (viewer / analyst / admin)" style="flex:1;min-width:240px">
          <button class="btn" onclick="signIn()">Sign in</button>
          <button class="btn secondary" onclick="closeKeyDialog()">Close</button>
        </div>
        <p id="key-msg" class="small" style="margin-top:10px;color:var(--muted)"></p>
        <div class="notice info" style="margin-top:12px"><span class="icon">🛡️</span>
          <div><strong>Roles:</strong> <b>viewer</b> – read-only incl. protected notes ·
          <b>analyst</b> – notes, triage, threat creation · <b>admin</b> – analyst rights + audit log.</div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    document.getElementById("key-input").focus();
  };
  window.closeKeyDialog = function () {
    const m = document.getElementById("key-modal");
    if (m) m.remove();
  };
  window.signOut = function () {
    sessionStorage.removeItem("ti_api_key");
    sessionStorage.removeItem("ti_api_role");
    refreshKeyBadge();
    window.location.reload();
  };
  window.signIn = async function () {
    const input = document.getElementById("key-input");
    const msg = document.getElementById("key-msg");
    const key = input.value.trim();
    if (!key) { msg.textContent = "Please paste a key first."; return; }
    sessionStorage.setItem("ti_api_key", key);
    try {
      const who = await api.get("/admin/whoami");
      sessionStorage.setItem("ti_api_role", who.role);
      msg.textContent = "✅ Signed in as role: " + who.role + ". Reloading…";
      setTimeout(() => window.location.reload(), 600);
    } catch (err) {
      sessionStorage.removeItem("ti_api_key");
      msg.textContent = "❌ " + (err.message || "Invalid key");
    }
  };
  window.refreshKeyBadge = function () {
    const badge = document.getElementById("key-badge");
    if (!badge) return;
    const role = sessionStorage.getItem("ti_api_role");
    if (role) {
      badge.classList.add("signed");
      badge.innerHTML = `🔑 ${escapeHtml(role)} · sign out`;
      badge.onclick = window.signOut;
    }
  };
  window.signedInRole = () => sessionStorage.getItem("ti_api_role");

  // ---------------- Toast --------------------------------------------------
  window.toast = function (message, kind = "good") {
    const t = document.createElement("div");
    t.style.cssText = `position:fixed;bottom:22px;right:22px;z-index:200;padding:12px 18px;border-radius:10px;` +
      `font-weight:600;font-size:13.5px;box-shadow:0 8px 30px rgba(0,0,0,.4);max-width:420px;` +
      (kind === "good"
        ? "background:#14532d;color:#bbf7d0;border:1px solid #22c55e"
        : "background:#450a0a;color:#fecaca;border:1px solid #ef4444");
    t.textContent = message;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 4200);
  };

  // ---------------- Chart defaults -----------------------------------------
  window.applyChartDefaults = function (Chart) {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.borderColor = "#1e2a4a";
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.plugins.legend.labels.boxWidth = 12;
    Chart.defaults.plugins.legend.labels.boxHeight = 12;
    Chart.defaults.plugins.tooltip.backgroundColor = "#0b1326";
    Chart.defaults.plugins.tooltip.borderColor = "#2b3b66";
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.maintainAspectRatio = false;
  };

  window.chartPalette = ["#22d3ee", "#818cf8", "#f472b6", "#facc15", "#34d399",
    "#fb923c", "#60a5fa", "#a78bfa", "#f87171", "#2dd4bf"];

  document.addEventListener("DOMContentLoaded", renderNavbar);
})();
