# GitHub Setup Instructions

> These commands prepare and push YOUR REAL repository. Nothing has been
> pushed yet — commit history exists only after you run these steps and
> capture the real screenshots (items 35 and 36 in the evidence checklist).
> Never fabricate GitHub evidence.

## 1. One-time global config (if you haven't already)

```bat
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
git init
```
(Use the email tied to your GitHub account so contributions link to your
profile.)

## 2. Initialize the repository (inside the project folder)

```bat
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
git init
git branch -M main
```

The included `.gitignore` already excludes `venv/`, `__pycache__/`,
`.env`, the SQLite database (regenerable) and OS noise — so `git add .`
is safe.

## 3. Recommended commit sequence (tells the project's story)

Stage and commit in logical chunks so the history demonstrates how the
project was built:

```bat
git add README.md requirements.txt .gitignore .env.example pytest.ini
git commit -m "Initialize cybersecurity threat intelligence dashboard"

git add data/generate_threat_data.py data/threat_intelligence_dataset.csv data/vulnerabilities.csv data/dataset_meta.json
git commit -m "Add synthetic threat intelligence dataset"

git add backend/services/ioc_validator.py
git commit -m "Implement IOC validation"

git add backend/services/enrichment_engine.py
git commit -m "Add threat enrichment engine"

git add backend/services/risk_engine.py
git commit -m "Implement risk and confidence scoring"

git add backend/services/correlation_engine.py
git commit -m "Add threat correlation"

git add backend/services/alert_engine.py
git commit -m "Implement security alert engine"

git add backend/services/attack_mapper.py
git commit -m "Add ATT&CK mapping module"

git add backend/services/vulnerability_service.py data/vulnerabilities.csv
git commit -m "Build vulnerability awareness module"

git add backend/database.py backend/models/ backend/utils/ backend/config.py
git commit -m "Design threat intelligence database schema"

git add backend/routes/ backend/app.py
git commit -m "Implement REST API with authentication and RBAC"

git add frontend/
git commit -m "Create SOC threat dashboard"

git add frontend/js/ioc_search.js
git commit -m "Add IOC search functionality"

git add frontend/threat-details.html frontend/js/threat_details.js
git commit -m "Build threat investigation view"

git add awareness/ frontend/awareness.html frontend/js/awareness.js
git commit -m "Create cybersecurity awareness center"

git add awareness/quiz_questions.json frontend/quiz.html frontend/js/quiz.js backend/routes/quiz.py
git commit -m "Add security awareness quiz"

git add backend/services/quiz_service.py frontend/executive_summary.html
git commit -m "Implement awareness scoring and executive summary"

git add tests/
git commit -m "Implement automated tests"

git add docs/ reports/ screenshots/ scripts/
git commit -m "Complete README and documentation"
```

(If you prefer, a single `git add .` + one commit also works — but the
sequenced history is stronger evidence of genuine development.)

## 4. Create the GitHub repository (in your browser)

1. Sign in to GitHub → **New repository**.
2. Repository name:
   `Cybersecurity-Awareness-Threat-Intelligence-Dashboard`
3. Description:
   `Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.`
4. Visibility: **Public** (so recruiters can see it).
5. Do **not** initialize with README/.gitignore/license (we already have them).
6. Click **Create repository**.

## 5. Push

```bat
git remote add origin https://github.com/<YOUR-USERNAME>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
git push -u origin main
```

(If you use SSH: `git remote set-url origin git@github.com:<YOUR-USERNAME>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git`.)

## 6. Add repository topics (on the GitHub repo page → ⚙️ About)

```
cybersecurity  threat-intelligence  cti  soc  ioc  mitre-attack
security-awareness  python  fastapi  vulnerability-management
incident-response  security-analytics  defensive-security
```

## 7. Capture the real GitHub evidence (manual steps)

* **Screenshot 35 — GitHub commits:** open
  `https://github.com/<user>/<repo>/commits/main` and capture the commit
  list → save as `screenshots/35_github_commits.png`.
* **Screenshot 36 — GitHub repository:** capture the repository front page
  (README rendered, topics visible) → save as
  `screenshots/36_github_repository.png`.
* **Screenshot 37 — README preview:** capture the README as rendered on
  GitHub → save as `screenshots/37_readme_preview.png`.

Update `screenshots/README.md` (mark those three rows as included) after
capturing them.

## 8. Optional extras that strengthen the profile

* Enable **GitHub Pages** from the `docs/` folder or add a link to the
  demo GIF in the README.
* Add a `LICENSE` (MIT is fine for a student project).
* Pin the repository on your profile (`Customize your pins`).
