/** IOC Search page: validation display + local database lookup results. */
window.quickSearch = function (value) {
  document.getElementById("search-input").value = value;
  doSearch();
};

window.doSearch = async function () {
  const input = document.getElementById("search-input");
  const area = document.getElementById("result-area");
  const q = input.value.trim();
  if (!q) { area.innerHTML = `<div class="notice warn"><span class="icon">✏️</span><div>Please enter an indicator to search.</div></div>`; return; }

  area.innerHTML = `<div class="loading"><div class="spinner"></div><div>Validating indicator and querying the local database…</div></div>`;

  // Step 1 - validation (always shown, even when search then fails)
  let validation;
  try {
    validation = await api.get("/indicators/validate?q=" + encodeURIComponent(q));
  } catch (err) { showError(area, err); return; }

  // Step 2 - database lookup
  let data = null, searchError = null;
  try {
    data = await api.get("/indicators/search?q=" + encodeURIComponent(q));
  } catch (err) {
    searchError = err; // e.g. invalid indicator -> 400 with validation payload
  }

  const v = validation;
  const known = data && data.known_in_demo_dataset;

  area.innerHTML = `
    <div class="panel">
      <h3>Validation result — “is this syntactically valid?”</h3>
      <p class="panel-sub">Validation checks FORMAT only. A valid indicator is not automatically malicious; an invalid one is safely rejected.</p>
      <div class="kv-grid">
        <div class="kv"><div class="k">Input</div><div class="v mono" style="word-break:break-all">${escapeHtml(q)}</div></div>
        <div class="kv"><div class="k">Valid syntax</div><div class="v">${v.valid ? '<span style="color:#4ade80;font-weight:700">✔ YES</span>' : '<span style="color:#f87171;font-weight:700">✘ NO</span>'}</div></div>
        <div class="kv"><div class="k">Indicator type</div><div class="v">${escapeHtml(v.indicator_type)} ${v.valid ? `(${escapeHtml(data ? data.coarse_type : v.indicator_type)})` : ""}</div></div>
        <div class="kv"><div class="k">Normalized value</div><div class="v mono" style="word-break:break-all">${escapeHtml(v.normalized_value)}</div></div>
      </div>
      <ul style="margin-top:12px;padding-left:20px">
        ${v.validation_notes.map(n => `<li class="small" style="margin-bottom:4px">${escapeHtml(n)}</li>`).join("")}
      </ul>
    </div>

    ${data ? `
    <div class="panel" style="margin-top:16px">
      <h3>Database lookup result</h3>
      <p class="panel-sub">Local synthetic dataset only — no external feeds, no outbound connections.</p>
      ${known ? `
        <div class="grid cols-4" style="margin-bottom:14px">
          <div class="stat-card c-crit"><div class="stat-value" style="color:${riskColor(data.risk)}">${data.risk}<span style="font-size:15px;color:var(--muted-2)">/100</span></div><div class="stat-label">Risk</div><div class="stat-hint">range ${data.risk_range.min}–${data.risk_range.max} across records</div></div>
          <div class="stat-card c-high"><div class="stat-value">${sevBadge(data.severity)}</div><div class="stat-label">Severity</div><div class="stat-hint">worst across records</div></div>
          <div class="stat-card c-good"><div class="stat-value" style="color:${confColor(data.confidence)}">${data.confidence}%</div><div class="stat-label">Confidence</div><div class="stat-hint">range ${data.confidence_range.min}–${data.confidence_range.max}</div></div>
          <div class="stat-card"><div class="stat-value">${data.observation_count}</div><div class="stat-label">Observations</div><div class="stat-hint">${data.distinct_sources.length} distinct sources</div></div>
        </div>
        <div class="kv-grid">
          <div class="kv"><div class="k">Known in demo dataset</div><div class="v"><span style="color:#4ade80;font-weight:700">YES</span> (${data.related_threats.length} record${data.related_threats.length === 1 ? "" : "s"})</div></div>
          <div class="kv"><div class="k">Associated category</div><div class="v">${data.associated_categories.map(catBadge).join(" ")}</div></div>
          <div class="kv"><div class="k">First seen</div><div class="v">${fmtDateTime(data.first_seen)}</div></div>
          <div class="kv"><div class="k">Last seen</div><div class="v">${fmtDateTime(data.last_seen)}</div></div>
          <div class="kv"><div class="k">Status (primary record)</div><div class="v">${statusBadge(data.status || "—")}</div></div>
          <div class="kv"><div class="k">Distinct sources</div><div class="v">${data.distinct_sources.map(escapeHtml).join(", ")}</div></div>
        </div>
        ${data.mitre_mapping.length ? `
          <div style="margin-top:14px"><div class="k" style="font-size:10.5px;color:var(--muted-2);font-weight:700;text-transform:uppercase">MITRE ATT&amp;CK mapping</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px">
            ${data.mitre_mapping.map(m => `<span class="badge attack" title="${escapeHtml(m.justification)}">${escapeHtml(m.technique_id)} · ${escapeHtml(m.tactic)}</span>`).join("")}
          </div></div>` : ""}
        ${data.related_indicators.length ? `
          <div style="margin-top:14px"><div class="k" style="font-size:10.5px;color:var(--muted-2);font-weight:700;text-transform:uppercase">Related indicators (correlation cluster)</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px">
            ${data.related_indicators.map(i => `<span class="badge type">${escapeHtml(i.indicator_value)}</span>`).join("")}
          </div></div>` : ""}
        ${data.analyst_notes.length ? `
          <div style="margin-top:14px"><div class="k" style="font-size:10.5px;color:var(--muted-2);font-weight:700;text-transform:uppercase">Analyst notes (authenticated)</div>
          ${data.analyst_notes.map(n => `<div class="kv" style="margin-top:6px"><div class="v">${escapeHtml(n.note)}</div></div>`).join("")}</div>` : ""}
        <div class="table-wrap" style="margin-top:16px"><table>
          <thead><tr><th>Threat ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Risk</th><th>Confidence</th><th>Status</th></tr></thead>
          <tbody>${data.related_threats.map(t => `
            <tr class="clickable" onclick="location.href='threat-details.html?id=${encodeURIComponent(t.threat_id)}'">
              <td class="mono">${escapeHtml(t.threat_id)}</td>
              <td class="ellip">${escapeHtml(t.threat_name)}</td>
              <td>${catBadge(t.category)}</td>
              <td>${sevBadge(t.severity)}</td>
              <td>${riskPill(t.risk_score)}</td>
              <td>${t.confidence_score}%</td>
              <td>${statusBadge(t.status)}</td>
            </tr>`).join("")}</tbody>
        </table></div>
        <div class="notice info" style="margin:14px 0 0"><span class="icon">🛡️</span><div>${escapeHtml(data.safety_notice)}</div></div>
      ` : `
        <div class="empty-state" style="padding:26px">
          <b>Not found in the demo dataset.</b><br>
          <span class="small muted">The indicator is syntactically valid but has no observations in the local
          synthetic data. No external lookup is performed — this application is fully offline by design.</span>
        </div>`}
    </div>` : `
    <div class="notice warn" style="margin-top:16px"><span class="icon">🚫</span>
      <div><b>Search skipped:</b> the input did not pass syntactic validation, so no database lookup
      was performed. ${escapeHtml(searchError ? searchError.message : "")}</div>
    </div>`}
  `;
};

document.getElementById("search-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") doSearch();
});
