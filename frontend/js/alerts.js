/** Alert queue page: list + investigation modal + status workflow. */
window.loadAlerts = async function (page = 1) {
  const area = document.getElementById("alert-table");
  showLoading(area, "Loading alert queue…");
  const params = new URLSearchParams({ page, page_size: 15 });
  const val = (id) => document.getElementById(id).value;
  if (val("f-status")) params.set("status", val("f-status"));
  if (val("f-sev")) params.set("severity", val("f-sev"));
  if (val("f-type")) params.set("alert_type", val("f-type"));

  let data;
  try { data = await api.get("/alerts?" + params.toString()); }
  catch (err) { showError(area, err); return; }

  // status cards
  const counts = data.status_counts;
  document.getElementById("status-cards").innerHTML = [
    { l: "New", v: counts.NEW || 0, cls: "c-info" },
    { l: "Investigating", v: counts.INVESTIGATING || 0, cls: "c-acc2" },
    { l: "Monitoring", v: counts.MONITORING || 0, cls: "c-high" },
    { l: "Resolved", v: counts.RESOLVED || 0, cls: "c-good" },
    { l: "False Positive", v: counts.FALSE_POSITIVE || 0, cls: "" },
    { l: "Total Alerts", v: data.total, cls: "" },
    { l: "Correlated (obs>1)", v: "see rows", cls: "" },
  ].map(c0 => `
    <div class="stat-card ${c0.cls}">
      <div class="stat-value">${escapeHtml(String(c0.v))}</div>
      <div class="stat-label">${escapeHtml(c0.l)}</div>
    </div>`).join("");

  if (!data.items.length) {
    area.innerHTML = `<div class="empty-state">No alerts match these filters.</div>`;
  } else {
    area.innerHTML = `<div class="table-wrap"><table>
      <thead><tr>
        <th>Alert</th><th>Type</th><th>Severity</th><th>Risk</th><th>Conf.</th>
        <th>Obs. count</th><th>Indicator</th><th>Linked threat</th><th>Status</th><th></th>
      </tr></thead>
      <tbody>
        ${data.items.map(a => `
          <tr>
            <td class="mono">#${a.alert_id}</td>
            <td class="small">${escapeHtml(a.alert_type.replace(/_/g, " "))}</td>
            <td>${sevBadge(a.severity)}</td>
            <td>${riskPill(a.risk_score)}</td>
            <td>${a.confidence_score}%</td>
            <td class="mono">${a.observation_count}${a.observation_count > 1 ? ' <span class="badge st-MONITORING">correlated</span>' : ""}</td>
            <td class="mono ellip" title="${escapeHtml(a.indicator_value || "")}">${escapeHtml(a.indicator_value || "—")}</td>
            <td><a href="threat-details.html?id=${encodeURIComponent(a.threat_id)}">${escapeHtml(a.threat_id)}</a></td>
            <td>${statusBadge(a.status)}</td>
            <td><a href="#" onclick="openInvestigation(${a.alert_id});return false">investigate →</a></td>
          </tr>`).join("")}
      </tbody></table></div>`;
  }

  document.getElementById("pager").innerHTML = `
    <span>${data.total} alert${data.total === 1 ? "" : "s"} · page ${data.page} / ${data.pages || 1}</span>
    <button class="btn secondary small" ${page <= 1 ? "disabled" : ""} onclick="loadAlerts(${page - 1})">← Prev</button>
    <button class="btn secondary small" ${page >= (data.pages || 1) ? "disabled" : ""} onclick="loadAlerts(${page + 1})">Next →</button>`;
};

window.resetAlertFilters = function () {
  ["f-status", "f-sev", "f-type"].forEach(id => (document.getElementById(id).value = ""));
  loadAlerts(1);
};

window.openInvestigation = async function (alertId) {
  let alert;
  try { alert = await api.get("/alerts/" + alertId); }
  catch (err) { toast(err.message, "bad"); return; }

  const t = alert.linked_threat || {};
  const signedIn = !!signedInRole();
  const modal = document.createElement("div");
  modal.className = "modal-backdrop";
  modal.id = "inv-modal";
  modal.innerHTML = `
    <div class="modal">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <h3 style="margin:0">Alert #${alert.alert_id} — investigation</h3>
        ${sevBadge(alert.severity)} ${statusBadge(alert.status)}
        <span style="flex:1"></span>
        <button class="btn secondary small" onclick="document.getElementById('inv-modal').remove()">Close ✕</button>
      </div>
      <p class="modal-sub">${escapeHtml(alert.description)}</p>
      <div class="kv-grid">
        <div class="kv"><div class="k">Alert type</div><div class="v">${escapeHtml(alert.alert_type.replace(/_/g, " "))}</div></div>
        <div class="kv"><div class="k">Raised</div><div class="v">${fmtDateTime(alert.created_at)}</div></div>
        <div class="kv"><div class="k">Risk / Confidence</div><div class="v">${alert.risk_score} / ${alert.confidence_score}%</div></div>
        <div class="kv"><div class="k">Observation count</div><div class="v">${alert.observation_count} ${alert.observation_count > 1 ? '<span class="badge st-MONITORING">correlated</span>' : ""}</div></div>
        <div class="kv"><div class="k">Indicator</div><div class="v mono">${escapeHtml(alert.indicator_value || "—")} <span class="badge st-FALSE_POSITIVE">SYNTHETIC</span></div></div>
        <div class="kv"><div class="k">Linked threat</div><div class="v"><a href="threat-details.html?id=${encodeURIComponent(alert.threat_id)}">${escapeHtml(alert.threat_id)}</a> · ${escapeHtml(t.threat_name || "")}</div></div>
      </div>
      ${alert.correlation_basis && alert.correlation_basis.length ? `
        <div class="notice info" style="margin-top:12px"><span class="icon">🔗</span>
          <div><b>Correlation basis:</b> ${alert.correlation_basis.map(escapeHtml).join(" · ")}<br>
          <span class="small">${escapeHtml(alert.attribution_note)}</span></div></div>` : ""}
      <div class="notice warn" style="margin-top:12px"><span class="icon">🛡️</span>
        <div class="small">IOC match ≠ automatic confirmed compromise. Investigate, enrich, correlate —
        then decide: escalate / monitor / resolve / false positive.</div></div>
      <div style="display:flex;gap:10px;margin-top:16px;align-items:center;flex-wrap:wrap">
        <div class="filter-group" style="flex:1;min-width:200px">
          <label>Update alert status ${signedIn ? "(analyst)" : "(sign in required)"}</label>
          <select id="alert-status-select" ${signedIn ? "" : "disabled"}>
            ${["NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"]
              .map(s => `<option ${s === alert.status ? "selected" : ""}>${s}</option>`).join("")}
          </select>
        </div>
        <button class="btn" onclick="updateAlertStatus(${alert.alert_id})" ${signedIn ? "" : "disabled"}>Update status</button>
      </div>
      <p class="small muted" style="margin-top:10px">Status changes are audited (actor role, timestamp, target).</p>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener("click", (e) => { if (e.target === modal) modal.remove(); });
};

window.updateAlertStatus = async function (alertId) {
  const status = document.getElementById("alert-status-select").value;
  try {
    await api.put(`/alerts/${alertId}/status`, { status });
    toast("Alert " + alertId + " → " + status + " (audited).");
    document.getElementById("inv-modal").remove();
    loadAlerts(1);
  } catch (err) { toast(err.message, "bad"); }
};

(async function init() {
  await loadAlerts(1);
  // deep link: alerts.html?alert=123
  const params = new URLSearchParams(window.location.search);
  if (params.get("alert")) openInvestigation(parseInt(params.get("alert"), 10));
})();
