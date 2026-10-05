# Interview Preparation — 10 Questions & 10 Strong Answers

*Exactly 10 predicted questions; the first is "Explain your project." The
answers sound like a student who genuinely implemented, tested, analyzed and
documented the system.*

---

### 1. Explain your project.

**Answer:** I developed a Cybersecurity Awareness & Threat Intelligence
Dashboard that combines technical threat-intelligence analysis with
cybersecurity awareness training. The technical side processes synthetic
threat records containing indicators such as IP addresses, domains, URLs,
file hashes, and vulnerability identifiers. The system validates indicators,
enriches them with local threat context, calculates separate risk and
confidence scores, correlates related observations, and displays them
through a SOC-style dashboard. I also added MITRE ATT&CK mapping where
sufficient behavioral context exists and a vulnerability-awareness module
with contextual prioritization. The awareness side contains learning modules
covering phishing, passwords, MFA, ransomware, social engineering, privacy,
and incident reporting, along with a 36-question quiz and personalized
learning recommendations. Everything is automated-tested with 72 tests, and
the project is entirely defensive, running fully offline on synthetic data.

### 2. What is Cyber Threat Intelligence?

**Answer:** Cyber Threat Intelligence, or CTI, is analyzed information
about cyber threats that helps an organization make better defensive
decisions. Raw data becomes more useful when it is validated,
contextualized, enriched, and assessed for relevance. Threat intelligence
can include indicators such as IP addresses, domains, URLs, and file
hashes, but it can also include information about adversary behaviors,
vulnerabilities, campaigns, and defensive context. My project demonstrates
the technical and tactical sides of CTI using a synthetic dataset of 2,200
records, with the full pipeline from ingestion to scoring to analyst
workflow.

### 3. What is an IOC, and does an IOC match prove that a system is compromised?

**Answer:** IOC stands for Indicator of Compromise. Examples include an IP
address, domain, URL, file hash, or other artifact associated with
suspicious activity. However, an IOC match alone does not prove compromise.
Indicators can become stale, IP addresses can be shared, infrastructure can
change ownership, and threat feeds can contain false positives. In my
project, an IOC match becomes evidence for investigation and is combined
with context, confidence, risk, source reliability, and related
observations. The dashboard states this explicitly: an IOC match is not
automatic confirmation of compromise.

### 4. What is the difference between risk score and confidence score in your dashboard?

**Answer:** Risk score represents how concerning a threat or indicator
could be, based on factors such as severity (30%), confidence (25%),
recency (15%), observation frequency (10%), source reliability (10%), and
correlation context (10%). Confidence score represents how strongly the
available evidence supports the intelligence assessment — it uses source
reliability, corroboration across independent sources, observation count,
and staleness penalties. For example, an indicator could have a risk score
of 90 but confidence of only 25 — that means the potential impact may be
serious, but the evidence is weak and needs further validation. Keeping
these scores separate prevents the system from treating uncertain
intelligence as confirmed fact, and every score returns a factor-by-factor
breakdown so analysts can see exactly why it was computed.

### 5. What is threat enrichment?

**Answer:** Threat enrichment means adding useful context to a raw security
indicator. For example, instead of showing only an IP address, my dashboard
can show its indicator type, first-seen and last-seen dates, associated
threat categories, risk and confidence scores, source reliability, related
observations, alerts, correlation-cluster indicators, ATT&CK mapping when
appropriate, and analyst notes. Enrichment helps a SOC analyst understand
whether an indicator is relevant and what additional investigation may be
required. Importantly, my enrichment engine works entirely from the local
synthetic database — it never contacts the indicator or calls any external
service.

### 6. What is MITRE ATT&CK, and how did you use it?

**Answer:** MITRE ATT&CK is a knowledge base describing adversary behaviors
observed in cyber operations. It organizes behavior into concepts such as
tactics, techniques, and sub-techniques. A tactic describes the adversary's
objective, while a technique describes a way that objective may be
achieved. In my project, I map synthetic threat records to ATT&CK only when
there is enough behavioral context — for example, a phishing lure domain
maps to Initial Access and T1566.002 Spearphishing Link. About 58% of my
records have justified mappings; the rest are explicitly left unmapped
because evidence is insufficient. I avoid assuming that an IP or domain
alone proves that a particular technique occurred, and I never invent
technique IDs — only well-known real ones from the public knowledge base.

### 7. How did you handle vulnerability prioritization?

**Answer:** I designed the vulnerability module so prioritization is not
based only on a CVSS score. The framework also considers asset criticality,
exposure, known exploitation evidence, and business context, with weights
of 35/20/20/15/10 percent. For example, in my synthetic dataset there is a
CVSS 9.8 CRITICAL vulnerability on an isolated test asset with no
exploitation evidence — it scores 52/100 priority. Meanwhile a CVSS 8.1
HIGH vulnerability on an internet-facing, mission-critical VPN gateway
with active exploitation evidence scores 93/100 and should be fixed first.
This demonstrates risk-based vulnerability management rather than simply
sorting by severity.

### 8. What is threat correlation and why is it important?

**Answer:** Threat correlation combines related security observations to
provide better context. For example, a domain, an IP address, and a file
hash may appear in related synthetic observations within the same time
window or threat cluster. Correlating them helps the analyst understand the
broader situation instead of investigating every event independently. I
also use correlation to reduce alert fatigue by grouping repeated
observations — the same indicator observed 100 times in 5 minutes produces
one correlated alert with an observation count of 100, instead of 100
separate analyst alerts. And importantly, correlation suggests
relationships; it does not by itself prove attribution, and my UI says so
on every correlation view.

### 9. How would a SOC analyst use your dashboard?

**Answer:** A SOC analyst could start with the alert queue, prioritize
items using severity, risk, and confidence, open the investigation view,
validate the indicator, review the enrichment — first/last seen, sources,
related observations — and check any justified ATT&CK mapping. The analyst
can then add investigation notes (which are access-controlled and require
an analyst API key), and change the status to investigating, monitoring,
resolved, or false positive — every change is audited and mirrored onto the
threat's timeline. The dashboard therefore demonstrates a simplified
workflow from raw threat information through triage, contextual analysis,
investigation, and documentation, which is exactly the Tier-1 analyst
process.

### 10. What are the limitations of threat intelligence, and how would you improve this project?

**Answer:** Threat intelligence has limitations because indicators can
become stale, infrastructure can be shared or reassigned, different feeds
can disagree, and correlation does not automatically prove attribution or
compromise. My current project uses synthetic data, so it demonstrates the
workflow rather than providing live operational intelligence. I would
improve it with authorized threat-feed integrations, STIX/TAXII support,
SIEM integration, CVE and known-exploitation feeds like CISA KEV, IOC
expiration, better deduplication and confidence scoring, automated
enrichment from approved sources, ATT&CK Navigator exports, and role-based
SOC dashboards — while maintaining the same defensive security controls:
no contact with indicators, authentication, RBAC, rate limiting, and audit
logging.

---

**Extra talking points that show depth**
* Why risk and confidence are separate: prevents automation from acting on
  weak evidence.
* Why analyst notes are access-controlled: threat-intel data reveals
  defensive posture (what you've detected, what's unpatched).
* Why validation checks syntax, not maliciousness: those are different
  questions requiring different evidence.
* Why the app is offline-only: an analysis tool should never become the
  source of traffic to an attacker's infrastructure.
