/** Executive summary: plain-language threat landscape for management. */
(async function () {
  applyChartDefaults(Chart);
  const root = document.getElementById("exec-root");
  let s;
  try { s = await api.get("/executive/summary"); }
  catch (err) { showError(root, err); return; }

  const c = s.counts;
  root.innerHTML = `
    <div class="notice warn"><span class="icon">📊</span><div>${escapeHtml(s.data_notice)}</div></div>

    <div class="panel" style="margin-top:16px">
      <h3>Threat landscape summary</h3>
      <p style="font-size:14.5px;margin-top:6px">${escapeHtml(s.threat_landscape_summary)}</p>
    </div>

    <div class="grid cols-7" style="margin-top:16px">
      ${[
        { l: "Threat records", v: c.total_threat_records, cls: "" },
        { l: "Critical (active)", v: c.critical_active, cls: "c-crit" },
        { l: "High (active)", v: c.high_active, cls: "c-high" },
        { l: "Open investigations", v: c.open_investigations, cls: "c-acc2" },
        { l: "Monitoring", v: c.monitoring, cls: "c-high" },
        { l: "False positives", v: c.false_positives, cls: "c-good" },
        { l: "New alerts", v: c.new_alerts, cls: "c-info" },
      ].map(x => `<div class="stat-card ${x.cls}">
          <div class="stat-value">${escapeHtml(String(x.v))}</div>
          <div class="stat-label">${escapeHtml(x.l)}</div></div>`).join("")}
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <div class="panel">
        <h3>Top threat categories</h3>
        <p class="panel-sub">Where the risk is concentrated</p>
        <div class="chart-box"><canvas id="chart-cat"></canvas></div>
      </div>
      <div class="panel">
        <h3>Top vulnerability categories</h3>
        <p class="panel-sub">Average contextual priority by product category</p>
        <div class="chart-box"><canvas id="chart-vuln"></canvas></div>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <div class="panel">
        <h3>Awareness score trend</h3>
        <p class="panel-sub">Average quiz score per month (${s.awareness.attempts} attempts, synthetic seed + demo)</p>
        ${s.awareness.trend.length ? `<div class="chart-box"><canvas id="chart-aware"></canvas></div>`
          : `<div class="empty-state">No quiz attempts recorded yet.</div>`}
        ${s.awareness.weakest_categories.length ? `
          <div style="margin-top:12px"><div class="k" style="font-size:10.5px;color:var(--muted-2);font-weight:700;text-transform:uppercase">Top awareness weaknesses</div>
          ${s.awareness.weakest_categories.map(w => `
            <div class="cat-score-row">
              <span class="cname">${escapeHtml(w.category)}</span>
              <div class="cbar"><i style="width:${w.average_score}%;background:#f97316"></i></div>
              <span class="cval">${w.average_score}%</span>
            </div>`).join("")}</div>` : ""}
      </div>
      <div class="panel">
        <h3>Vulnerability posture</h3>
        <p class="panel-sub">Contextual priority view</p>
        <div class="kv-grid">
          <div class="kv"><div class="k">Critical-priority vulnerabilities</div><div class="v" style="color:#f87171;font-weight:800;font-size:20px">${s.vulnerability_summary.critical_priority}</div></div>
          <div class="kv"><div class="k">Without vendor patch</div><div class="v" style="color:#fb923c;font-weight:800;font-size:20px">${s.vulnerability_summary.without_vendor_patch}</div></div>
        </div>
        <p class="small muted" style="margin-top:10px">Vulnerabilities are prioritized by CVSS
        <b>plus</b> asset criticality, exposure, exploitation evidence and business context —
        not CVSS alone.</p>
        <div class="notice info" style="margin-top:10px;margin-bottom:0"><span class="icon">📖</span>
          <div class="small"><b>Reading guide:</b> ${escapeHtml(s.reading_guide.risk_vs_confidence)}
          ${escapeHtml(s.reading_guide.ioc_disclaimer)}</div></div>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <h3>Recommended defensive priorities</h3>
      <p class="panel-sub">Plain-language actions for the next planning cycle</p>
      ${s.recommended_defensive_priorities.map(p => `
        <div class="kv" style="margin-bottom:10px">
          <div class="k"><span class="badge sev-${p.priority === "P1" ? "CRITICAL" : p.priority === "P2" ? "HIGH" : p.priority === "P3" ? "MEDIUM" : "LOW"}">${escapeHtml(p.priority)}</span> ${escapeHtml(p.title)}</div>
          <div class="v small">${escapeHtml(p.detail)}</div>
        </div>`).join("")}
    </div>
  `;

  const catLabels = s.top_threat_categories.map(x => x.category);
  new Chart(document.getElementById("chart-cat"), {
    type: "bar",
    data: { labels: catLabels, datasets: [{ data: s.top_threat_categories.map(x => x.count), backgroundColor: "#22d3ee", borderRadius: 4 }] },
    options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: "#18223d" } } } },
  });

  new Chart(document.getElementById("chart-vuln"), {
    type: "bar",
    data: { labels: s.top_vulnerability_categories.map(x => x.category),
            datasets: [{ label: "avg priority", data: s.top_vulnerability_categories.map(x => x.avg_priority), backgroundColor: "#f472b6", borderRadius: 4 }] },
    options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, max: 100, grid: { color: "#18223d" } } } },
  });

  if (s.awareness.trend.length) {
    new Chart(document.getElementById("chart-aware"), {
      type: "line",
      data: {
        labels: s.awareness.trend.map(t => t.month),
        datasets: [{
          label: "average score %", data: s.awareness.trend.map(t => t.average_score),
          borderColor: "#34d399", backgroundColor: "rgba(52,211,153,.12)", fill: true, tension: .3,
        }],
      },
      options: { plugins: { legend: { display: false } }, scales: { y: { min: 0, max: 100, grid: { color: "#18223d" } } } },
    });
  }
})();
