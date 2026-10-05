/** Security Quiz: server-graded questions, category scores, recommendations. */
(async function () {
  const root = document.getElementById("quiz-root");
  let quiz;
  try { quiz = await api.get("/quiz"); }
  catch (err) { showError(root, err); return; }

  document.getElementById("quiz-sub").textContent =
    `${quiz.total_questions} questions across ${quiz.categories.length} categories. ` +
    "Answers are graded server-side; correct answers are never sent to the browser before submission.";

  const state = { answers: {}, submitted: false };

  root.innerHTML = `
    <div class="panel" style="margin-top:16px">
      <div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center">
        <div class="filter-group" style="min-width:200px">
          <label>Category filter</label>
          <select id="cat-filter"><option value="">All categories</option>
            ${quiz.categories.map(c => `<option>${escapeHtml(c)}</option>`).join("")}</select>
        </div>
        <div class="filter-group">
          <label>Anonymous label (optional — no personal data is collected)</label>
          <input type="text" id="anon-id" placeholder="e.g. demo-student-01" maxlength="60">
        </div>
        <div style="flex:1"></div>
        <div style="text-align:right">
          <div class="stat-value" id="progress-num" style="font-size:20px">0 / ${quiz.questions.length}</div>
          <div class="stat-label">answered</div>
        </div>
      </div>
    </div>

    <div id="questions-area" style="margin-top:16px"></div>
    <div id="submit-area" style="margin-top:18px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <button class="btn" id="submit-btn" onclick="submitQuiz()" style="padding:13px 26px;font-size:15px">Submit answers &amp; see score</button>
      <span class="small muted">Score calculated on the server — refreshing never reveals answers.</span>
    </div>
    <div id="result-area" style="margin-top:20px"></div>
  `;

  const letters = ["A", "B", "C", "D"];

  function renderQuestions() {
    const cat = document.getElementById("cat-filter").value;
    const qs = cat ? quiz.questions.filter(q => q.category === cat) : quiz.questions;
    document.getElementById("questions-area").innerHTML = qs.map((q, i) => `
      <div class="quiz-q">
        <div class="q-head">
          <span class="q-num">${i + 1}</span>
          <div>
            <div class="q-text">${escapeHtml(q.question)}</div>
            <span class="badge cat" style="margin-top:6px">${escapeHtml(q.category)}</span>
          </div>
        </div>
        ${q.options.map((opt, oi) => `
          <div class="opt" id="opt-${q.question_id}-${oi}" onclick="selectOption('${q.question_id}', ${oi})">
            <span class="opt-letter">${letters[oi]}</span>
            <span>${escapeHtml(opt)}</span>
            <span class="feedback" id="fb-${q.question_id}-${oi}"></span>
          </div>`).join("")}
      </div>`).join("");
  }
  renderQuestions();
  document.getElementById("cat-filter").addEventListener("change", renderQuestions);

  window.selectOption = function (questionId, optionIndex) {
    if (state.submitted) return;
    state.answers[questionId] = optionIndex;
    quiz.questions.find(q => q.question_id === questionId).options.forEach((_, oi) => {
      const el = document.getElementById(`opt-${questionId}-${oi}`);
      if (el) el.classList.remove("selected");
    });
    const el = document.getElementById(`opt-${questionId}-${optionIndex}`);
    if (el) el.classList.add("selected");
    document.getElementById("progress-num").textContent =
      `${Object.keys(state.answers).length} / ${quiz.questions.length}`;
  };

  window.submitQuiz = async function () {
    const answered = Object.keys(state.answers).length;
    if (answered < quiz.questions.length) {
      if (!confirm(`You answered ${answered} of ${quiz.questions.length} questions. Unanswered questions count as incorrect. Submit anyway?`)) return;
    }
    const btn = document.getElementById("submit-btn");
    btn.disabled = true; btn.textContent = "Grading…";
    const answers = Object.entries(state.answers).map(([question_id, selected_option]) =>
      ({ question_id, selected_option }));
    let result;
    try {
      result = await api.post("/quiz/submit", {
        answers,
        anonymous_user_id: document.getElementById("anon-id").value.trim() || null,
      });
    } catch (err) {
      toast(err.message, "bad");
      btn.disabled = false; btn.textContent = "Submit answers & see score";
      return;
    }
    state.submitted = true;
    btn.textContent = "Submitted ✔";

    // reveal per-question correctness (client-side highlight only; grading was server-side)
    quiz.questions.forEach(q => {
      const sel = state.answers[q.question_id];
      q.options.forEach((_, oi) => {
        const fb = document.getElementById(`fb-${q.question_id}-${oi}`);
        const el = document.getElementById(`opt-${q.question_id}-${oi}`);
        if (!fb || !el) return;
        if (oi === sel) { el.classList.add(sel === undefined ? "" : "wrong"); fb.textContent = ""; }
      });
    });

    renderResult(result);
    document.getElementById("result-area").scrollIntoView({ behavior: "smooth" });
  };

  function renderResult(r) {
    document.getElementById("result-area").innerHTML = `
      <div class="panel">
        <h3>📊 Your Awareness Score</h3>
        <div class="score-hero-big">
          <div class="big" style="color:${r.overall_score >= 81 ? "#4ade80" : r.overall_score >= 61 ? "#a3e635" : r.overall_score >= 41 ? "#facc15" : "#f87171"}">${r.overall_score}%</div>
          <div class="band">${escapeHtml(r.band)}</div>
          <div class="muted small">${r.correct_count} of ${r.question_count} questions correct</div>
        </div>
        <div class="notice info" style="margin-top:8px"><span class="icon">🎓</span><div class="small">${escapeHtml(r.educational_note)}</div></div>

        <h4 style="margin-top:18px;color:var(--accent)">Category scores</h4>
        ${Object.entries(r.category_scores).map(([cat, score]) => `
          <div class="cat-score-row">
            <span class="cname">${escapeHtml(cat)}</span>
            <div class="cbar"><i style="width:${score}%;background:${score >= 81 ? "#22c55e" : score >= 61 ? "#84cc16" : score >= 41 ? "#eab308" : "#ef4444"}"></i></div>
            <span class="cval">${score}%</span>
          </div>`).join("")}

        <div class="grid cols-2" style="margin-top:18px">
          <div>
            <h4 style="color:var(--accent)">Weakest areas</h4>
            ${r.weakest_areas.length ? r.weakest_areas.map(w => `
              <div class="kv" style="margin-top:8px">
                <div class="k">${escapeHtml(w.category)}</div>
                <div class="v">${w.score}%</div>
              </div>`).join("") : `<p class="small muted" style="margin-top:8px">No category below 100% — strong performance across the board.</p>`}
          </div>
          <div>
            <h4 style="color:var(--accent)">Recommended learning modules</h4>
            ${r.recommendations.map(rec => {
              if (rec.module_ids && rec.module_ids.length) {
                return `<div class="kv" style="margin-top:8px">
                  <div class="v small"><b>${escapeHtml(rec.message)}</b><br>
                  ${rec.module_ids.map(mid => `<a href="awareness.html?module=${encodeURIComponent(mid)}" style="margin-right:10px">→ open module</a>`).join("")}
                  </div></div>`;
              }
              return `<div class="kv" style="margin-top:8px"><div class="v small">${escapeHtml(rec.message)}</div></div>`;
            }).join("")}
          </div>
        </div>
      </div>
    `;
  }
})();
