/** Vulnerability awareness page: teaching examples + prioritized CVE table + detail modal. */
window.loadVulns = async function () {
  const area = document.getElementById("vuln-table");
  showLoading(area, "Loading synthetic vulnerabilities…");
  const params = new URLSearchParams({ sort: document.getElementById("f-sort").value });
  const sev = document.getElementById("f-sev").value;
  const cat = document.getElementById("f-cat").value.trim();
  if (sev) params.set("severity", sev);
  if (cat) params.set("product_category", cat);

  let data;
  try { data = await api.get("/vulnerabilities?" + params.toString()); }
  catch (err) { showError(area, err); return; }

  area.innerHTML = `
    <p class="small muted" style="margin-bottom:10px">
      ${data.total} synthetic vulnerabilities · priority bands:
      ${Object.entries(data.priority_band_counts).map(([b, n]) => `<span class="badge sev-${b}">${b}: ${n}</span>`).join(" ")}
      · <b>${escapeHtml(data.prioritization_note)}</b></p>
    <div class="table-wrap"><table>
      <thead><tr>
        <th>CVE ID</th><th>Product category</th><th>Severity</th><th>CVSS</th>
        <th>Priority</th><th>Exposure</th><th>Exploitation (demo)</th><th>Patch</th><th>Published</th><th></th>
      </tr></thead>
      <tbody>
        ${data.items.map(v => `
          <tr>
            <td class="mono">${escapeHtml(v.cve_id)}</td>
            <td>${escapeHtml(v.product_category)}</td>
            <td>${sevBadge(v.severity)}</td>
            <td class="mono">${v.cvss_score}</td>
            <td>${riskPill(v.priority_score)} <span class="small muted">${escapeHtml(v.priority_band)}</span></td>
            <td class="small">${escapeHtml(v.exposure)}</td>
            <td class="small">${escapeHtml(v.exploitation_status_demo.replace(" (synthetic)", ""))}</td>
            <td>${v.patch_available ? '<span style="color:#4ade80">✔</span>' : '<span style="color:#f87171">✘</span>'}</td>
            <td class="small nowrap">${fmtDate(v.published_date)}</td>
            <td><a href="#" onclick="openVuln('${escapeHtml(v.cve_id)}');return false">details →</a></td>
          </tr>`).join("")}
      </tbody></table></div>`;
};

window.openVuln = async function (cveId) {
  let v;
  try { v = await api.get("/vulnerabilities/" + encodeURIComponent(cveId)); }
  catch (err) { toast(err.message, "bad"); return; }
  const modal = document.createElement("div");
  modal.className = "modal-backdrop";
  modal.id = "vuln-modal";
  modal.innerHTML = `
    <div class="modal">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <h3 style="margin:0" class="mono">${escapeHtml(v.cve_id)}</h3>
        ${sevBadge(v.severity)} <span class="badge cat">priority ${v.priority_score} · ${escapeHtml(v.priority_band)}</span>
        <span style="flex:1"></span>
        <button class="btn secondary small" onclick="document.getElementById('vuln-modal').remove()">Close ✕</button>
      </div>
      <p class="modal-sub">${escapeHtml(v.product_name)} — ${escapeHtml(v.product_category)}</p>
      <p style="font-size:14px">${escapeHtml(v.description)}</p>
      <div class="kv-grid" style="margin-top:12px">
        <div class="kv"><div class="k">CVSS score</div><div class="v">${v.cvss_score} / 10</div></div>
        <div class="kv"><div class="k">Published</div><div class="v">${fmtDate(v.published_date)}</div></div>
        <div class="kv"><div class="k">Asset criticality</div><div class="v">${v.asset_criticality} / 5</div></div>
        <div class="kv"><div class="k">Exposure</div><div class="v">${escapeHtml(v.exposure)}</div></div>
        <div class="kv"><div class="k">Exploitation status</div><div class="v">${escapeHtml(v.exploitation_status_demo)}</div></div>
        <div class="kv"><div class="k">Patch available</div><div class="v">${v.patch_available ? "Yes" : "No — compensating controls required"}</div></div>
        <div class="kv"><div class="k">Business context</div><div class="v">${escapeHtml(v.business_context)}</div></div>
      </div>
      <h4 style="margin-top:16px;color:var(--accent)">Contextual priority breakdown (${v.priority_score}/100)</h4>
      ${v.priority_breakdown.map(f => `
        <div class="factor-row">
          <span class="fname">${escapeHtml(f.factor)}</span>
          <div class="fbar"><i style="width:${f.component_score}%"></i></div>
          <span class="fval">${f.contribution}</span>
          <span class="fwt">${Math.round(f.weight * 100)}%</span>
        </div>`).join("")}
      <p class="small muted" style="margin-top:8px">${escapeHtml(v.priority_interpretation)}</p>
      <h4 style="margin-top:14px;color:var(--accent)">Recommended defensive actions</h4>
      <ul style="padding-left:20px;margin-top:6px">
        ${v.recommended_actions.map(a => `<li style="font-size:13.5px;margin-bottom:6px">${escapeHtml(a)}</li>`).join("")}
      </ul>
      <div class="notice warn" style="margin-top:12px;margin-bottom:0"><span class="icon">⚖️</span>
        <div class="small">Defensive awareness only — this record is synthetic and contains no
        exploitation instructions.</div></div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener("click", (e) => { if (e.target === modal) modal.remove(); });
};

(async function init() {
  // Teaching examples A vs B
  try {
    const [a, b] = await Promise.all([
      api.get("/vulnerabilities/CVE-2026-900001"),
      api.get("/vulnerabilities/CVE-2026-900002"),
    ]);
    document.getElementById("teaching-examples").innerHTML = `
      <div class="kv" style="margin-bottom:10px">
        <div class="k">${escapeHtml(a.cve_id)} — CVSS ${a.cvss_score} CRITICAL, isolated lab asset</div>
        <div class="v">Priority <b style="color:${riskColor(a.priority_score)}">${a.priority_score}/100</b> (${escapeHtml(a.priority_band)}) — high technical severity, low operational urgency.</div>
      </div>
      <div class="kv">
        <div class="k">${escapeHtml(b.cve_id)} — CVSS ${b.cvss_score} HIGH, internet-facing critical VPN</div>
        <div class="v">Priority <b style="color:${riskColor(b.priority_score)}">${b.priority_score}/100</b> (${escapeHtml(b.priority_band)}) — <b>fix this first</b>: exposure + criticality + active exploitation outweigh the lower CVSS.</div>
      </div>`;
  } catch (_) { /* table still loads */ }
  await loadVulns();
})();
