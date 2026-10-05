# SOC Investigation Workflow & Incident-Response Awareness

## The workflow this dashboard implements (brief section 33)

```
Threat Feed
   ↓
IOC Detected
   ↓
Validation            ← ioc_validator.py (syntax only — never "is it malicious?")
   ↓
Enrichment            ← enrichment_engine.py (local database context only)
   ↓
Risk + Confidence     ← risk_engine.py (two SEPARATE scores)
   ↓
Alert                 ← alert_engine.py (thresholds; duplicates correlated)
   ↓
SOC Queue             ← alerts.html (severity-ordered)
   ↓
Analyst Triage        ← tier-1 workflow below
   ↓
Correlation           ← correlation_engine.py (evidence, not attribution)
   ↓
Investigation         ← threat-details.html (timeline, notes, ATT&CK, CVE)
   ↓
Escalate / Monitor / Resolve / False Positive
   ↓
Documentation         ← analyst notes (protected) + audit log
```

## Tier-1 SOC analyst workflow (how to use this dashboard)

1. **Start in the alert queue** (Alerts page). NEW alerts are sorted by
   severity — triage CRITICAL/HIGH first.
2. **Open the investigation view** — read the description, check risk and
   confidence, and remember: high risk + low confidence = "corroborate
   before acting".
3. **Validate the indicator** — IOC Search shows the indicator type,
   whether it's known, first/last seen, sources. An indicator last seen two
   years ago is probably stale.
4. **Enrich** — the threat detail page shows categories, related alerts,
   related indicators and any justified ATT&CK mapping.
5. **Consider benign explanations FIRST** — shared infrastructure, CDNs,
   security scanners, marketing platforms, stale feeds. Most false
   positives die here.
6. **Correlate** — check the RELATED THREAT CLUSTER: is the same campaign
   hitting multiple indicators? Are other sources corroborating?
7. **Decide and document**:
   * **Escalate** (UNDER_REVIEW / escalate to Tier 2) when evidence supports
     real malicious relevance,
   * **Monitor** when relevance is plausible but unconfirmed,
   * **Resolve** when handled,
   * **False Positive** when benign — with a note explaining why.
8. **Update the alert status** — every change is audited and mirrored to
   the threat timeline.

## Alert fatigue and alert correlation (brief section 32)

If the same indicator fires 100 times in 5 minutes, 100 separate alerts
would bury the queue and train analysts to ignore alerts — that is **alert
fatigue**, and it is how real incidents get missed. The alert engine
therefore merges repeated observations into **one correlated alert with
`observation_count = 100`**, so the analyst sees the full picture in a
single triage item. (Demonstration endpoint:
`POST /api/alerts/correlate-demo`.)

## Incident-response lifecycle (brief section 34, educational)

```
Preparation → Detection/Identification → Containment → Eradication → Recovery → Lessons Learned
```

* **Preparation** — policies, backups, logging, playbooks, training.
* **Detection / Identification** — an alert becomes a confirmed security
  event.
* **Containment** — stop the spread (isolate systems, block indicators,
  revoke credentials).
* **Eradication** — remove the root cause (malware, accounts,
  vulnerabilities, persistence).
* **Recovery** — restore from clean backups and verify health.
* **Lessons learned** — post-incident review; improvements feed back into
  preparation.

Terminology differs between frameworks (e.g., NIST's "Post-Incident
Activity" vs SANS "Lessons Learned") — the phases are consistent.

## User incident-response checklist (non-destructive, educational)

1. Recognize the warning signs (clicked link, unexpected MFA prompt, lost
   device, odd system behaviour).
2. Stop interacting — do not reply, revisit links or "test" attachments.
3. Report immediately through the known channel.
4. Preserve evidence: keep messages, note times, do not delete or power
   off devices unless instructed.
5. Change credentials quickly if you disclosed them (email account first).
6. Follow IT/security instructions; stay reachable.
7. Afterwards, complete the recommended awareness module.

> This project includes **no destructive response actions** — responders
> follow their organization's approved IR plan.
