# Cybersecurity Awareness & Threat Intelligence — Concepts

*Part of the project documentation: plain-language + technical explanations of
every core concept (project-brief sections 1-4, 6, 11, 14, 16, 34).*

---

## 1. Key concepts — simple and technical explanations

### What is cybersecurity awareness?
**Simple:** Teaching people to recognize and avoid security risks — spotting
a phishing email, using strong passwords, knowing what to report.
**Technical:** The human layer of defense-in-depth: training, nudges and
processes that reduce the likelihood that a user performs an exploitable
action (credential disclosure, malware execution, data exposure).

### What is cyber threat intelligence (CTI)?
**Simple:** Collected and analyzed information about cyber threats that
helps defenders make better decisions.
**Technical:** The lifecycle (planning → collection → processing → analysis
→ dissemination → feedback) that turns raw indicators and reports into
assessed, contextualized, actionable intelligence with explicit confidence.

### What is an IOC (Indicator of Compromise)?
**Simple:** A clue — like an IP address, domain, URL or file hash — that may
be associated with malicious activity.
**Technical:** A technical artifact observed in telemetry or feeds that can
be searched for in internal systems. **Limitation:** IOCs go stale, are
shared by benign infrastructure (CDNs, cloud hosts, dynamic IPs), and always
require context. **IOC match ≠ automatic confirmed compromise.**

### What is an IOA (Indicator of Attack/Activity)?
**Simple:** Evidence that an attack is *in progress* — behavior, not just an
artifact.
**Technical:** Behavioral patterns (e.g., a process making unusual DNS
requests, credential dumping attempts) that indicate adversary actions.
IOAs are harder to evade than IOCs because they describe *how* the adversary
behaves, not *what* they used.

### What is a vulnerability? A CVE? CVSS?
**Simple:** A weakness in software that could be abused; a CVE is its public
catalog ID; CVSS is a 0-10 severity score.
**Technical:** A vulnerability is a flaw exploitable to violate
confidentiality/integrity/availability. CVE IDs (`CVE-YYYY-NNNN`) identify
publicly catalogued vulnerabilities. CVSS (Common Vulnerability Scoring
System) scores technical severity — but operational priority also needs
asset criticality, exposure, exploitation evidence and business context
(see the Vulnerability module).

### What is a threat feed?
**Simple:** A stream of threat information (usually IOCs/CVEs) you can
consume automatically.
**Technical:** Machine-readable collections (CSV/JSON/STIX) of indicators
with metadata (first/last seen, confidence, tags). This project uses a
**synthetic local feed** so it works offline and never contacts real
infrastructure.

### What is a threat actor (conceptually)?
**Simple:** The person or group behind an attack.
**Technical:** An individual or group (script kiddie, crime syndicate,
APT, insider) with intent, capability and opportunity. This project
deliberately avoids actor attribution — correlation is evidence, not
attribution.

### What are TTPs?
**Simple:** the adversary's Tactics, Techniques and Procedures — their
playbook.
**Technical:** Tactics = objectives (why), techniques = methods (how),
procedures = specific implementations. MITRE ATT&CK catalogs these.

### What is MITRE ATT&CK?
**Simple:** A big, free knowledge base of attacker behaviors.
**Technical:** A matrix of tactics (Reconnaissance → Impact) and techniques
(e.g., T1566 Phishing, T1486 Data Encrypted for Impact) used for detection
engineering, gap analysis and communication. **IOC = WHAT was observed;
ATT&CK = HOW behavior may relate to techniques.**

### What is threat enrichment?
**Simple:** Adding context to a raw clue — who saw it, when, how often, what
it's linked to.
**Technical:** Joining an indicator with internal/external context:
first/last seen, corroboration, related alerts, cluster membership, ATT&CK
mapping, analyst notes. This project enriches **locally only**.

### What is threat correlation?
**Simple:** Connecting related clues into a bigger picture.
**Technical:** Grouping observations by shared campaign, indicator, time
window or category. **Correlation indicates relationship — it does not
prove attribution.**

### What is threat hunting?
**Simple:** Proactively searching for attackers who may already be inside,
instead of waiting for alerts.
**Technical:** Hypothesis-driven searches across telemetry (often ATT&CK-
aligned) to find malicious activity that automated detections missed.

### What is a SOC?
**Simple:** The team/room where security alerts are watched and investigated
24/7.
**Technical:** Security Operations Center — people, process and technology
(SIEM, EDR, case management) performing monitoring, triage, investigation,
escalation and response. See docs/soc_workflow.md.

---

## 2. Awareness vs Threat Intelligence — and how this project combines them

| | Cybersecurity Awareness | Threat Intelligence |
|---|---|---|
| Audience | Every user | SOC / security / IT teams |
| Question | "How do I avoid being tricked?" | "What is attacking us and how concerning is it?" |
| Output | Behaviour change | Prioritized defensive action |
| Examples | Phishing training, MFA nudges | IOC analysis, risk scoring, ATT&CK mapping |

**This project combines HUMAN DEFENSE + TECHNICAL THREAT INTELLIGENCE:**
the executive dashboard merges the threat landscape with awareness scores
and weaknesses, and threat categories link to awareness modules (e.g., a
phishing-heavy feed recommends the Phishing Awareness module).

## 3. Industry relevance

Threat-intelligence dashboards are used by: **SOCs** (triage context),
**banks** (fraud + APT tracking), **cloud companies** (multi-tenant
detection), **IT enterprises** (patching priorities), **government**
(national CSIRT advisories), **e-commerce** (fraud/abuse), **healthcare**
(ransomware resilience), **universities** (open networks + awareness),
**MSSPs** (multi-customer intel), and **consulting** (assessment + purple
team context).

Relevant roles this project demonstrates: **SOC Analyst** (queue, triage,
status workflow), **Cybersecurity Analyst** (analytics, dashboards),
**Threat Intelligence Analyst** (scoring, enrichment, correlation),
**Incident Response Analyst** (IR lifecycle awareness, timelines),
**Security Engineer** (APIs, auth, rate limiting, audit), **Vulnerability
Analyst** (contextual prioritization), **Security Awareness Specialist**
(modules, quiz, recommendations), **Threat Hunter** (ATT&CK-aligned context,
weak links).

## 4. Threat-intelligence types

| Type | Audience | Question | Example |
|---|---|---|---|
| **Strategic** | Executives | "Who threatens us and why? What's the trend?" | Annual threat landscape report |
| **Tactical** | Architects/defenders | "What TTPs should we defend against?" | ATT&CK mapping of a campaign |
| **Operational** | Incident responders | "Is a specific campaign active against us?" | Campaign indicators, imminent attack warning |
| **Technical** | SOC tools/analysts | "Which IOCs do we search/block?" | IPs, domains, hashes, CVEs |

**This student project focuses on Technical + Tactical intelligence, plus
Awareness-oriented output** (executive summary + learning center) — a
deliberate, realistic slice of a full CTI program.

## 5. IOC lifecycle (implemented in the UI and DB)

```
Observed → Validated → Enriched → Scored → Investigated → Monitored → Expired/Closed
```

Indicators **expire** because they go stale: infrastructure is reassigned,
attacks rotate domains, and shared platforms create benign reuse.

## 6. Risk vs confidence (the core distinction)

* **Risk score = "How concerning may this be?"** (severity, confidence of
  the item, recency, frequency, source reliability, correlation context)
* **Confidence score = "How strong is the evidence?"** (source reliability,
  corroboration, observation count, staleness)

`Risk 90 / Confidence 25` → potentially serious, weakly evidenced —
corroborate before acting. `Risk 70 / Confidence 95` → well-supported,
meaningful risk. **High risk never automatically means confirmed
compromise.**

## 7. CVE, CVSS, vulnerability, patch, exploit, zero-day (conceptual)

* **Vulnerability** — a weakness. **CVE** — its catalog identifier.
* **CVSS** — technical severity 0-10.
* **Patch** — vendor fix. **Exploit** (conceptually) — code/technique that
  abuses a vulnerability (no instructions in this project, ever).
* **Zero-day** (conceptually) — a vulnerability exploited before a patch
  exists; compensating controls and detection become the defense.

## 8. Incident-response lifecycle (educational)

```
Preparation → Detection/Identification → Containment → Eradication → Recovery → Lessons Learned
```

Exact terminology varies by framework (NIST, SANS, ISO), but the phases are
consistent. Checklists and preparation — not heroics — decide outcomes.
