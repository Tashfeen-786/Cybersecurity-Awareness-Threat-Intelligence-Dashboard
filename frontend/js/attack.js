/** MITRE ATT&CK page: tactics overview, technique frequency, drill-down to threats. */
(async function () {
  applyChartDefaults(Chart);
  const root = document.getElementById("attack-root");
  let summary;
  try { summary = await api.get("/attack/summary"); }
  catch (err) { showError(root, err); return; }

  root.innerHTML = `
    <div class="grid cols-3" style="margin:18px 0 16px">
      <div class="stat-card"><div class="stat-value">${summary.mapped_threats}</div><div class="stat-label">Mapped threats</div><div class="stat-hint">with justified behavioural context</div></div>
      <div class="stat-card c-high"><div class="stat-value">${summary.unmapped_threats}</div><div class="stat-label">Unmapped threats</div><div class="stat-hint">insufficient context — mapping omitted</div></div>
      <div class="stat-card c-info"><div class="stat-value">${summary.technique_frequency.length}</div><div class="stat-label">Distinct techniques</div><div class="stat-hint">real ATT&amp;CK IDs, never invented</div></div>
    </div>

    <div class="grid cols-2">
      <div class="panel">
        <h3>Top ATT&amp;CK tactics</h3>
        <p class="panel-sub">Threat records by tactic (mapped only)</p>
        <div class="chart-box tall"><canvas id="chart-tactics"></canvas></div>
      </div>
      <div class="panel">
        <h3>Threats by tactic</h3>
        <p class="panel-sub">Click a tactic to view its threat records</p>
        <div id="tactic-list"></div>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <h3>Technique frequency</h3>
      <p class="panel-sub">Click a technique to see the associated synthetic threat records</p>
      <div id="tech-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px;margin-top:6px"></div>
    </div>

    <div id="drilldown" style="margin-top:16px"></div>
  `;

  // tactics chart
  new Chart(document.getElementById("chart-tactics"), {
    type: "bar",
    data: {
      labels: summary.top_tactics.map(t => t.tactic),
      datasets: [{ data: summary.top_tactics.map(t => t.count), backgroundColor: "#f472b6", borderRadius: 4 }],
    },
    options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: "#18223d" } } } },
  });

  // tactic list
  document.getElementById("tactic-list").innerHTML = summary.top_tactics.map(t => `
    <div class="cat-score-row" style="cursor:pointer" onclick="drillTactic('${escapeHtml(t.tactic)}')">
      <span class="cname">${escapeHtml(t.tactic)}</span>
      <div class="cbar"><i style="width:${Math.min(100, t.count * 3)}%;background:#f472b6"></i></div>
      <span class="cval">${t.count}</span>
    </div>`).join("");

  // technique cards
  document.getElementById("tech-grid").innerHTML = summary.technique_frequency.slice(0, 18).map(t => `
    <div class="kv" style="cursor:pointer;border-color:#3b2a4a" onclick="drillTechnique('${escapeHtml(t.technique_id)}')">
      <div class="k"><span class="badge attack">${escapeHtml(t.technique_id)}</span> ${escapeHtml(t.tactic)}</div>
      <div class="v small">${escapeHtml(t.technique || "")} · <b>${t.count}</b> record${t.count === 1 ? "" : "s"}</div>
    </div>`).join("");

  window.drillTactic = async function (tactic) {
    const box = document.getElementById("drilldown");
    showLoading(box, "Loading threats for tactic " + tactic + "…");
    try {
      const data = await api.get("/attack/tactics/" + encodeURIComponent(tactic));
      box.innerHTML = `
        <div class="panel">
          <h3>Tactic: ${escapeHtml(tactic)} <span class="badge cat">${data.count} records</span></h3>
          <div class="table-wrap" style="margin-top:10px"><table>
            <thead><tr><th>Threat</th><th>Category</th><th>Technique</th><th>Indicator</th><th>Severity</th><th>Risk</th><th>Status</th></tr></thead>
            <tbody>${data.threats.map(t => `
              <tr class="clickable" onclick="location.href='threat-details.html?id=${encodeURIComponent(t.threat_id)}'">
                <td class="ellip" title="${escapeHtml(t.threat_name)}">${escapeHtml(t.threat_name)}<br><span class="mono small muted">${escapeHtml(t.threat_id)}</span></td>
                <td>${catBadge(t.threat_category)}</td>
                <td><span class="badge attack">${escapeHtml(t.technique_id || "")}</span></td>
                <td class="mono ellip">${escapeHtml(t.indicator_value)}</td>
                <td>${sevBadge(t.severity)}</td>
                <td>${riskPill(t.risk_score)}</td>
                <td>${statusBadge(t.status)}</td>
              </tr>`).join("")}</tbody>
          </table></div>
        </div>`;
    } catch (err) { showError(box, err); }
  };

  window.drillTechnique = async function (techId) {
    const box = document.getElementById("drilldown");
    showLoading(box, "Loading threats for technique " + techId + "…");
    try {
      const data = await api.get("/attack/techniques/" + encodeURIComponent(techId));
      box.innerHTML = `
        <div class="panel">
          <h3>Technique: ${escapeHtml(data.technique_label || techId)} <span class="badge cat">${data.count} records</span></h3>
          <p class="panel-sub">${escapeHtml(data.note)}</p>
          <div class="table-wrap"><table>
            <thead><tr><th>Threat</th><th>Category</th><th>Indicator</th><th>Severity</th><th>Risk</th><th>Confidence</th><th>Status</th></tr></thead>
            <tbody>${data.threats.map(t => `
              <tr class="clickable" onclick="location.href='threat-details.html?id=${encodeURIComponent(t.threat_id)}'">
                <td class="ellip">${escapeHtml(t.threat_name)}<br><span class="mono small muted">${escapeHtml(t.threat_id)}</span></td>
                <td>${catBadge(t.threat_category)}</td>
                <td class="mono ellip">${escapeHtml(t.indicator_value)}</td>
                <td>${sevBadge(t.severity)}</td>
                <td>${riskPill(t.risk_score)}</td>
                <td>${t.confidence_score}%</td>
                <td>${statusBadge(t.status)}</td>
              </tr>`).join("")}</tbody>
          </table></div>
        </div>`;
    } catch (err) { showError(box, err); }
  };

  // deep-link support: mitre_attack.html?technique=T1566.002
  const params = new URLSearchParams(window.location.search);
  if (params.get("technique")) drillTechnique(params.get("technique"));
  else if (params.get("tactic")) drillTactic(params.get("tactic"));
})();
