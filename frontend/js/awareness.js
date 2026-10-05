/** Awareness Center: module grid + full module modal with the 5 required sections. */
const MODULE_ICONS = {
  "phishing-awareness": "🎣", "password-security": "🔑", "multi-factor-authentication": "🔐",
  "social-engineering": "🎭", "safe-browsing": "🌐", "secure-wifi": "📶",
  "software-updates": "🔄", "ransomware-awareness": "🛡️", "usb-media-safety": "🔌",
  "data-privacy": "🗃️", "mobile-security": "📱", "remote-work-security": "🏠",
  "cloud-account-security": "☁️", "incident-reporting": "🚨", "ai-scam-awareness": "🤖",
};

(async function () {
  const grid = document.getElementById("module-grid");
  let data;
  try { data = await api.get("/awareness/modules"); }
  catch (err) { showError(grid, err); return; }

  grid.innerHTML = data.modules.map(m => `
    <div class="module-card" onclick="openModule('${escapeHtml(m.module_id)}')">
      <span class="m-icon">${MODULE_ICONS[m.module_id] || "📘"}</span>
      <h4>${escapeHtml(m.title)}</h4>
      <div class="m-sum">${escapeHtml(m.summary)}</div>
      <div class="m-meta">
        <span>${escapeHtml(m.category)}</span>
        <span>⏱ ${m.reading_minutes} min read</span>
      </div>
    </div>`).join("");

  window.openModule = async function (moduleId) {
    let m;
    try { m = await api.get("/awareness/modules/" + encodeURIComponent(moduleId)); }
    catch (err) { toast(err.message, "bad"); return; }
    const c = m.content;
    const section = (icon, title, body) => `
      <div class="section-block">
        <h4>${icon} ${title}</h4>
        ${Array.isArray(body) ? `<ul>${body.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : `<p style="font-size:14px">${escapeHtml(body)}</p>`}
      </div>`;
    const modal = document.createElement("div");
    modal.className = "modal-backdrop";
    modal.id = "module-modal";
    modal.innerHTML = `
      <div class="modal">
        <div style="display:flex;align-items:center;gap:12px">
          <span style="font-size:30px">${MODULE_ICONS[m.module_id] || "📘"}</span>
          <div style="flex:1">
            <h3 style="margin:0">${escapeHtml(m.title)}</h3>
            <p class="modal-sub" style="margin:2px 0 0">${escapeHtml(m.category)} · ${m.reading_minutes} min read · defensive education only</p>
          </div>
          <button class="btn secondary small" onclick="document.getElementById('module-modal').remove()">Close ✕</button>
        </div>
        ${section("❓", "What is it?", c.what_is_it)}
        ${section("⚠️", "Why does it matter?", c.why_it_matters)}
        ${section("🚩", "Warning signs", c.warning_signs)}
        ${section("✅", "Safe practices", c.safe_practices)}
        ${section("🚨", "What to do if something happens", c.if_it_happens)}
        <div class="notice good" style="margin:6px 0 0"><span class="icon">🎓</span>
          <div class="small">Learned something? <a href="quiz.html">Test yourself in the Security Quiz →</a></div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener("click", (e) => { if (e.target === modal) modal.remove(); });
  };

  // deep link: awareness.html?module=phishing-awareness
  const params = new URLSearchParams(window.location.search);
  if (params.get("module")) openModule(params.get("module"));
})();
