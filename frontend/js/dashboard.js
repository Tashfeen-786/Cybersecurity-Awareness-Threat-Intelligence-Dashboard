/** Threat Dashboard: KPI cards, 10 charts, filterable recent-threat table. */
(async function () {
  applyChartDefaults(Chart);
  const charts = {};

  function mkChart(id, cfg) {
    const el = document.getElementById(id);
    if (!el) return;
    charts[id] = new Chart(el, cfg);
  }

  // ------------------------------------------------------------------ cards
  async function loadStats() {
    try {
      const stats = await api.get("/dashboard/stats");
      const c = stats.cards;
      const cards = [
        { v: c.total_threat_records, l: "Total Threat Records", cls: "", hint: "synthetic records" },
        { v: c.critical_threats, l: "Critical Threats", cls: "c-crit", hint: "active, not closed/FP" },
        { v: c.high_threats, l: "High Threats", cls: "c-high", hint: "active, not closed/FP" },
        { v: c.active_indicators, l: "Active Indicators", cls: "c-info", hint: "distinct indicator values" },
        { v: c.open_investigations, l: "Open Investigations", cls: "c-acc2", hint: "NEW + UNDER_REVIEW" },
        { v: c.average_confidence + "%", l: "Average Confidence", cls: "c-good", hint: "evidence quality (not risk)" },
        { v: c.vulnerabilities_tracked, l: "Vulnerabilities Tracked", cls: "", hint: "synthetic CVEs" },
      ];
      document.getElementById("cards").innerHTML = cards.map(c0 => `
        <div class="stat-card ${c0.cls}">
          <div class="stat-value">${escapeHtml(String(c0.v))}</div>
          <div class="stat-label">${escapeHtml(c0.l)}</div>
          <div class="stat-hint">${escapeHtml(c0.hint)}</div>
        </div>`).join("");
      return stats;
    } catch (err) {
      document.getElementById("cards").innerHTML =
        `<div class="error-box" style="grid-column:1/-1">⚠ ${escapeHtml(err.message)}</div>`;
      throw err;
    }
  }

  async function loadTrends() {
    const t = await api.get("/dashboard/trends");
    const s = await api.get("/dashboard/stats");

    const bar = (labels, data, color) => ({
      type: "bar",
      data: { labels, datasets: [{ data, backgroundColor: color, borderRadius: 4, maxBarThickness: 42 }] },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: "#18223d" } } } },
    });

    // 1 threats over time (line)
    const months = t.threats_over_time.map(x => x.period);
    mkChart("chart-over-time", {
      type: "line",
      data: {
        labels: months,
        datasets: [{
          data: t.threats_over_time.map(x => x.count), borderColor: "#22d3ee",
          backgroundColor: "rgba(34,211,238,.12)", fill: true, tension: .35,
          pointRadius: 3, pointBackgroundColor: "#22d3ee",
        }],
      },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: "#18223d" } } } },
    });

    // 2 severity
    mkChart("chart-severity", bar(
      s.charts.threats_by_severity.map(x => x.label.replace("INFORMATIONAL", "INFO")),
      s.charts.threats_by_severity.map(x => x.count),
      ["#64748b", "#22c55e", "#eab308", "#f97316", "#ef4444"]));

    // 3 category (horizontal bar)
    const cats = s.charts.threats_by_category;
    mkChart("chart-category", {
      type: "bar",
      data: { labels: cats.map(x => x.label), datasets: [{ data: cats.map(x => x.count), backgroundColor: "#818cf8", borderRadius: 4 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: "#18223d" } } } },
    });

    // 4 IOC types (doughnut)
    mkChart("chart-ioc", {
      type: "doughnut",
      data: { labels: s.charts.ioc_type_distribution.map(x => x.label),
              datasets: [{ data: s.charts.ioc_type_distribution.map(x => x.count), backgroundColor: chartPalette, borderWidth: 0 }] },
      options: { cutout: "58%", plugins: { legend: { position: "right" } } },
    });

    // 5 top tactics (horizontal)
    const tac = s.charts.top_attack_tactics.slice(0, 8);
    mkChart("chart-tactics", {
      type: "bar",
      data: { labels: tac.map(x => x.label), datasets: [{ data: tac.map(x => x.count), backgroundColor: "#f472b6", borderRadius: 4 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: "#18223d" } } } },
    });

    // 6 risk distribution
    const riskColors = ["#64748b", "#22c55e", "#eab308", "#f97316", "#ef4444"];
    mkChart("chart-risk", bar(
      t.risk_distribution.map(x => x.label.replace(" (", "\n(").split("\n")[0]),
      t.risk_distribution.map(x => x.count), riskColors));

    // 7 confidence distribution
    mkChart("chart-confidence", bar(
      t.confidence_distribution.map(x => x.label.split(" (")[0]),
      t.confidence_distribution.map(x => x.count),
      ["#ef4444", "#f97316", "#eab308", "#84cc16", "#22c55e"]));

    // 8 vulnerabilities by severity
    mkChart("chart-vulnsev", bar(
      s.charts.vulnerabilities_by_severity.map(x => x.label),
      s.charts.vulnerabilities_by_severity.map(x => x.count),
      ["#22c55e", "#eab308", "#f97316", "#ef4444"]));

    // 9 top threat categories (polar area)
    mkChart("chart-topcat", {
      type: "polarArea",
      data: { labels: s.charts.top_threat_categories.map(x => x.label),
              datasets: [{ data: s.charts.top_threat_categories.map(x => x.count), backgroundColor: chartPalette.map(c => c + "cc"), borderWidth: 0 }] },
      options: { plugins: { legend: { position: "right" } }, scales: { r: { grid: { color: "#18223d" }, ticks: { display: false } } } },
    });

    // 10 status distribution
    mkChart("chart-status", {
      type: "doughnut",
      data: { labels: s.charts.threat_status_distribution.map(x => x.label.replace(/_/g, " ")),
              datasets: [{ data: s.charts.threat_status_distribution.map(x => x.count),
                           backgroundColor: ["#38bdf8", "#a78bfa", "#f59e0b", "#64748b", "#10b981"], borderWidth: 0 }] },
      options: { cutout: "58%", plugins: { legend: { position: "right" } } },
    });
  }

  // ------------------------------------------------------------- table
  let categoriesLoaded = false;

  async function loadCategoryFilter() {
    if (categoriesLoaded) return;
    const stats = await api.get("/dashboard/stats");
    const sel = document.getElementById("f-category");
    (stats.charts.threats_by_category || []).forEach(c0 => {
      const o = document.createElement("option");
      o.textContent = c0.label; sel.appendChild(o);
    });
    categoriesLoaded = true;
  }

  window.loadThreats = async function (page = 1) {
    const area = document.getElementById("table-area");
    showLoading(area, "Querying local threat database…");
    const params = new URLSearchParams();
    const val = (id) => document.getElementById(id).value;
    if (val("f-severity")) params.set("severity", val("f-severity"));
    if (val("f-category")) params.set("category", val("f-category"));
    if (val("f-type")) params.set("indicator_type", val("f-type"));
    if (val("f-status")) params.set("status", val("f-status"));
    if (val("f-risk")) params.set("min_risk", val("f-risk"));
    if (val("f-conf")) params.set("min_confidence", val("f-conf"));
    if (val("f-from")) params.set("date_from", val("f-from"));
    if (val("f-to")) params.set("date_to", val("f-to"));
    if (val("f-q")) params.set("q", val("f-q"));
    params.set("sort", val("f-sort") || "newest");
    params.set("page", page);
    params.set("page_size", 15);
    try {
      const data = await api.get("/threats?" + params.toString());
      if (!data.items.length) {
        area.innerHTML = `<div class="empty-state">No threat records match these filters.</div>`;
      } else {
        area.innerHTML = `
          <div class="table-wrap"><table>
            <thead><tr>
              <th>Threat ID</th><th>Threat Name</th><th>Category</th><th>Indicator</th>
              <th>Severity</th><th>Risk</th><th>Confidence</th><th>First Seen</th>
              <th>Last Seen</th><th>Obs.</th><th>Status</th>
            </tr></thead>
            <tbody>
              ${data.items.map(t => `
                <tr class="clickable" onclick="location.href='threat-details.html?id=${encodeURIComponent(t.threat_id)}'">
                  <td class="mono">${escapeHtml(t.threat_id)}</td>
                  <td class="ellip" title="${escapeHtml(t.threat_name)}">${escapeHtml(t.threat_name)}</td>
                  <td>${catBadge(t.threat_category)}</td>
                  <td class="mono ellip" title="${escapeHtml(t.indicator_value)}">${escapeHtml(t.indicator_value)}</td>
                  <td>${sevBadge(t.severity)}</td>
                  <td>${riskPill(t.risk_score)}</td>
                  <td><span style="color:${confColor(t.confidence_score)};font-weight:700">${t.confidence_score}%</span></td>
                  <td class="nowrap small">${fmtDate(t.first_seen)}</td>
                  <td class="nowrap small">${fmtDate(t.last_seen)}</td>
                  <td class="mono">${t.observation_count}</td>
                  <td>${statusBadge(t.status)}</td>
                </tr>`).join("")}
            </tbody>
          </table></div>`;
      }
      const pager = document.getElementById("pager");
      pager.innerHTML = `
        <span>${data.total} record${data.total === 1 ? "" : "s"} · page ${data.page} / ${data.pages}</span>
        <button class="btn secondary small" ${page <= 1 ? "disabled" : ""} onclick="loadThreats(${page - 1})">← Prev</button>
        <button class="btn secondary small" ${page >= data.pages ? "disabled" : ""} onclick="loadThreats(${page + 1})">Next →</button>`;
    } catch (err) {
      showError(area, err);
    }
  };

  window.resetFilters = function () {
    ["f-severity", "f-category", "f-type", "f-status", "f-risk", "f-conf",
     "f-from", "f-to", "f-q"].forEach(id => (document.getElementById(id).value = ""));
    document.getElementById("f-sort").value = "newest";
    loadThreats(1);
  };

  document.getElementById("f-q").addEventListener("keydown", e => {
    if (e.key === "Enter") loadThreats(1);
  });

  try {
    await loadStats();
    await loadTrends();
    await loadCategoryFilter();
    await loadThreats(1);
  } catch (err) {
    const area = document.getElementById("table-area");
    if (area && !area.querySelector(".error-box")) showError(area, err);
  }
})();
