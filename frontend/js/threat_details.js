/** Threat Detail page: full SOC investigation view for one threat record. */
(async function () {
  const root = document.getElementById("detail-root");
  const params = new URLSearchParams(window.location.search);
  const threatId = params.get("id") || "THR-2026-001";

  let threat;
  try {
    threat = await api.get("/threats/" + encodeURIComponent(threatId));
  } catch (err) {
    showError(root, err);
    return;
  }

  document.title = threat.threat_id + " · " + threat.threat_name;

  const notesProtected = threat.notes_access !== "granted";
  const signedIn = !!signedInRole();

  root.innerHTML = `
    <div class="detail-head">
      <button class="btn secondary small" onclick="location.href='threat-dashboard.html'">← Dashboard</button>
      <div>
        <h1 style="font-size:22px">${escapeHtml(threat.threat_name)}</h1>
        <p class="muted mono">${escapeHtml(threat.threat_id)} · ${catBadge(threat.threat_category)} ${sevBadge(threat.severity)} ${statusBadge(threat.status)}
          <span class="badge st-NEW">SYNTHETIC / DEMO ONLY</span></p>
      </div>
      <div class="spacer" style="flex:1"></div>
      <div class="filter-group">
        <label>Update status (analyst)</label>
        <div style="display:flex;gap:8px">
          <select id="status-select">
            ${["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
              .map(s => `<option ${s === threat.status ? "selected" : ""}>${s}</option>`).join("")}
          </select>
          <button class="btn small" onclick="updateStatus()">Save</button>
        </div>
      </div>
    </div>

    <div class="notice info"><span class="icon">🛡️</span>
      <div><b>IOC match ≠ automatic confirmed compromise.</b> This record is evidence supporting an
      investigation. High risk does not automatically mean confirmed compromise, and correlation does
      not prove attribution. ${escapeHtml(threat.correlation_note || "")}</div>
    </div>

    <!-- Scores -->
    <div class="grid cols-2">
      <div class="panel">
        <h3>Risk score — “how concerning may this be?”</h3>
        <div class="score-hero">
          <div class="score-dial">
            <div class="num" style="color:${riskColor(threat.risk_score)}">${threat.risk_score}<span style="font-size:18px;color:var(--muted-2)">/100</span></div>
            <div class="lbl">${escapeHtml(sevBand(threat.risk_score))} risk band</div>
            <div class="sub">severity-driven · explainable</div>
          </div>
          <div style="flex:1;min-width:240px">
            ${threat.risk_breakdown.map(f => `
              <div class="factor-row">
                <span class="fname">${escapeHtml(f.factor)}</span>
                <div class="fbar"><i style="width:${f.component_score}%"></i></div>
                <span class="fval">${f.contribution}</span>
                <span class="fwt">${Math.round(f.weight * 100)}%</span>
              </div>`).join("")}
            <p class="small muted" style="margin-top:8px">${escapeHtml(threat.risk_interpretation)}</p>
          </div>
        </div>
      </div>
      <div class="panel">
        <h3>Confidence score — “how strong is the evidence?”</h3>
        <div class="score-hero">
          <div class="score-dial">
            <div class="num" style="color:${confColor(threat.confidence_score)}">${threat.confidence_score}<span style="font-size:18px;color:var(--muted-2)">/100</span></div>
            <div class="lbl">evidence quality</div>
            <div class="sub">source · corroboration · freshness</div>
          </div>
          <div style="flex:1;min-width:240px">
            <div class="kv-grid" style="grid-template-columns:1fr 1fr">
              <div class="kv"><div class="k">Source</div><div class="v">${escapeHtml(threat.source_name)}</div></div>
              <div class="kv"><div class="k">Source reliability</div><div class="v">${escapeHtml(threat.source_reliability || "—")}</div></div>
              <div class="kv"><div class="k">Observations</div><div class="v">${threat.observation_count}</div></div>
              <div class="kv"><div class="k">Campaign cluster</div><div class="v">${threat.campaign_id ? escapeHtml(threat.campaign_id) : "—"}</div></div>
            </div>
            <div class="notice warn" style="margin:10px 0 0"><span class="icon">💡</span>
              <div class="small"><b>Risk vs confidence:</b> risk = potential concern; confidence = evidence quality.
              A high-risk/low-confidence record needs corroboration before action.</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Identity fields -->
    <div class="panel" style="margin-top:16px">
      <h3>Indicator &amp; description</h3>
      <div class="kv-grid" style="margin-top:10px">
        <div class="kv"><div class="k">Indicator type</div><div class="v">${typeBadge(threat.indicator_type)}</div></div>
        <div class="kv"><div class="k">Indicator value</div><div class="v mono">${escapeHtml(threat.indicator_value)} <span class="badge st-FALSE_POSITIVE">SYNTHETIC</span></div></div>
        <div class="kv"><div class="k">First seen</div><div class="v">${fmtDateTime(threat.first_seen)}</div></div>
        <div class="kv"><div class="k">Last seen</div><div class="v">${fmtDateTime(threat.last_seen)}</div></div>
        <div class="kv"><div class="k">Region</div><div class="v">${escapeHtml(threat.country_or_region || "—")}</div></div>
        <div class="kv"><div class="k">CVE association</div><div class="v">${threat.cve_id ? `<a href="vulnerabilities.html">${escapeHtml(threat.cve_id)}</a>` : "—"}</div></div>
      </div>
      <p style="margin-top:12px;font-size:14px">${escapeHtml(threat.description || "No description.")}</p>
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <!-- ATT&CK -->
      <div class="panel">
        <h3>🎯 MITRE ATT&amp;CK mapping</h3>
        <p class="panel-sub">Mapped only where behavioural context justifies it — never guessed.</p>
        <div id="attack-box">
          ${threat.attack_mapping[0] && threat.attack_mapping[0].technique_id ? threat.attack_mapping.map(m => `
            <div class="kv" style="margin-bottom:10px">
              <div class="k">Tactic</div><div class="v">${escapeHtml(m.tactic)}</div>
              <div class="k" style="margin-top:8px">Technique</div>
              <div class="v"><span class="badge attack">${escapeHtml(m.technique_id)}</span> ${escapeHtml(m.technique || "")}</div>
              <div class="k" style="margin-top:8px">Justification</div><div class="v small muted">${escapeHtml(m.justification)}</div>
            </div>`).join("") + `
            <p class="small muted">IOC tells us <b>WHAT</b> artifact was observed; ATT&amp;CK helps describe <b>HOW</b> behaviour may relate to adversary techniques.</p>`
          : `<div class="empty-state">No ATT&amp;CK mapping — insufficient behavioural context.<br>
             <span class="small">Mapping is intentionally omitted rather than guessed, and technique IDs are never invented.</span></div>`}
        </div>
      </div>

      <!-- Related indicators & threats -->
      <div class="panel">
        <h3>🔗 Related indicators &amp; threats (correlation cluster)</h3>
        <p class="panel-sub">Correlation indicates relationship/evidence — it does <b>not</b> prove attribution.</p>
        ${threat.related_indicators && threat.related_indicators.length ? `
          <div class="k">Shared indicators in cluster</div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 14px">
            ${threat.related_indicators.map(i => `<span class="badge type" title="${escapeHtml(i.threat_id || "")}">${escapeHtml(i.indicator_value)}</span>`).join("")}
          </div>` : `<p class="small muted">No related indicators found.</p>`}
        ${threat.related_threats && threat.related_threats.length ? `
          <div class="k" style="margin-bottom:6px">Cluster members</div>
          <div class="table-wrap"><table>
            <thead><tr><th>ID</th><th>Name</th><th>Indicator</th><th>Risk</th><th>Conf.</th><th>Status</th></tr></thead>
            <tbody>${threat.related_threats.map(t => `
              <tr class="clickable" onclick="location.href='threat-details.html?id=${encodeURIComponent(t.threat_id)}'">
                <td class="mono">${escapeHtml(t.threat_id)}</td>
                <td class="ellip">${escapeHtml(t.threat_name)}</td>
                <td class="mono ellip">${escapeHtml(t.indicator_value)}</td>
                <td>${riskPill(t.risk_score)}</td>
                <td>${t.confidence_score}%</td>
                <td>${statusBadge(t.status)}</td>
              </tr>`).join("")}</tbody>
          </table></div>` : ""}
        ${threat.weak_links && threat.weak_links.length ? `
          <p class="small muted" style="margin-top:10px"><b>Weak links (analyst review required):</b>
          ${threat.weak_links.map(w => escapeHtml(w.threat_id + " — " + w.basis)).join(" · ")}</p>` : ""}
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <!-- Alerts -->
      <div class="panel">
        <h3>🚨 Related alerts</h3>
        <p class="panel-sub">Generated by the alert engine; duplicates correlated to avoid alert fatigue.</p>
        <div id="alerts-box"></div>
      </div>

      <!-- Timeline -->
      <div class="panel">
        <h3>🕐 Investigation timeline</h3>
        <p class="panel-sub">First seen → observations → risk change → investigation → monitoring → closed</p>
        <ul class="timeline" id="timeline-box"></ul>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <!-- Analyst notes -->
      <div class="panel">
        <h3>📝 Analyst notes</h3>
        <p class="panel-sub">Protected content — requires an authenticated API key.</p>
        <div id="notes-box">
          ${notesProtected ? `
            <div class="notice warn"><span class="icon">🔒</span>
              <div>Analyst notes are protected. <b>Sign in</b> (top-right, any demo API key from
              <span class="mono">.env.example</span>) to view them — threat-intel data and investigation
              notes reveal defensive posture, so they require access control.</div></div>` :
            (threat.analyst_notes.length ? threat.analyst_notes.map(n => `
              <div class="kv" style="margin-bottom:10px">
                <div class="k">${fmtDateTime(n.created_at)} · ${escapeHtml(n.author_role || "analyst")}</div>
                <div class="v">${escapeHtml(n.note)}</div>
              </div>`).join("") : `<p class="small muted">No notes yet.</p>`)}
        </div>
        <div style="display:flex;gap:10px;margin-top:14px;align-items:flex-start">
          <textarea id="note-input" rows="2" placeholder="${signedIn ? "Add an investigation note (stored sanitized, audited)…" : "Sign in as analyst to add notes…"}" ${signedIn ? "" : "disabled"}></textarea>
          <button class="btn" onclick="addNote()" ${signedIn ? "" : "disabled"}>Add note</button>
        </div>
      </div>

      <!-- Recommended actions -->
      <div class="panel">
        <h3>🛡️ Recommended defensive actions</h3>
        <p class="panel-sub">Defensive guidance only — no offensive instructions, ever.</p>
        <div class="section-block" style="margin-top:8px">
          <ul>
            ${threat.recommended_defensive_actions.map(a => `<li>${escapeHtml(a)}</li>`).join("")}
          </ul>
        </div>
        ${threat.cve_association ? `
          <div class="kv" style="margin-top:8px">
            <div class="k">Associated vulnerability</div>
            <div class="v"><a href="vulnerabilities.html">${escapeHtml(threat.cve_association.cve_id)}</a>
              · CVSS ${threat.cve_association.cvss_score} · priority ${threat.cve_association.priority_score}/100 (${escapeHtml(threat.cve_association.priority_band)})</div>
          </div>` : ""}
      </div>
    </div>
  `;

  function sevBand(score) {
    return score >= 81 ? "CRITICAL" : score >= 61 ? "HIGH" : score >= 41 ? "MEDIUM" : score >= 21 ? "LOW" : "INFORMATIONAL";
  }

  // ------------------------------------------------------------- alerts
  const alertsBox = document.getElementById("alerts-box");
  if (threat.related_alerts && threat.related_alerts.length) {
    alertsBox.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Obs. count</th><th>Status</th><th></th></tr></thead>
      <tbody>${threat.related_alerts.map(a => `
        <tr>
          <td class="mono">#${a.alert_id}</td>
          <td class="small">${escapeHtml(a.alert_type.replace(/_/g, " "))}</td>
          <td>${sevBadge(a.severity)}</td>
          <td class="mono">${a.observation_count}</td>
          <td>${statusBadge(a.status)}</td>
          <td><a href="alerts.html?alert=${a.alert_id}">investigate →</a></td>
        </tr>`).join("")}</tbody></table></div>`;
  } else {
    alertsBox.innerHTML = `<div class="empty-state">No alerts linked to this threat (risk/confidence below thresholds).</div>`;
  }

  // ------------------------------------------------------------- timeline
  document.getElementById("timeline-box").innerHTML = threat.timeline.map(ev => `
    <li class="tl-${escapeHtml(ev.event_type)}">
      <div class="tl-type">${escapeHtml(ev.event_type.replace(/_/g, " "))}</div>
      <div class="tl-desc">${escapeHtml(ev.description)}</div>
      <div class="tl-date">${fmtDateTime(ev.occurred_at)}</div>
    </li>`).join("");

  // ------------------------------------------------------------- actions
  window.updateStatus = async function () {
    const status = document.getElementById("status-select").value;
    try {
      await api.put("/threats/" + encodeURIComponent(threat.threat_id), { status });
      toast("Status updated to " + status + " (audited).");
      setTimeout(() => window.location.reload(), 700);
    } catch (err) { toast(err.message, "bad"); }
  };

  window.addNote = async function () {
    const note = document.getElementById("note-input").value.trim();
    if (note.length < 3) { toast("Note is too short.", "bad"); return; }
    try {
      await api.post(`/threats/${encodeURIComponent(threat.threat_id)}/notes`, { note });
      toast("Note added (sanitized + audited).");
      setTimeout(() => window.location.reload(), 700);
    } catch (err) { toast(err.message, "bad"); }
  };
})();
