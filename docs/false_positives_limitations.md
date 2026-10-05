# False Positives & Intelligence Limitations

Threat intelligence **supports analyst decisions**. It must never be
treated as unquestionable truth. This document explains why — and what this
dashboard does about it.

## Why IOC matches produce false positives

* **Shared IP infrastructure** — one IP may serve thousands of unrelated
  customers (cloud providers, CDNs, hosting). A "malicious IP" may simply be
  a shared platform where one tenant misbehaved. Blocking it can break
  legitimate business.
* **Changing domain ownership** — domains expire and are re-registered. An
  indicator from a two-year-old report may now belong to a completely
  innocent party.
* **Cloud infrastructure** — the same ranges host both benign services and
  attacker infrastructure; context (which tenant, which path) matters more
  than the IP alone.
* **Stale indicators** — attacker infrastructure rotates fast (hours to
  days). Old IOCs lose value and raise false-positive rates. Real programs
  implement **IOC expiration** (see the IOC lifecycle).
* **Conflicting threat feeds** — different vendors disagree: one flags an
  indicator malicious, another benign. Disagreement is information: it
  usually means context is missing and confidence should drop.
* **Confidence limitations** — confidence is a model of evidence quality
  (source reliability, corroboration, freshness), not a guarantee. A
  single-source, uncorroborated report is a hypothesis to test.

## Correlation and attribution limits

* **Correlation indicates relationship/evidence — it does NOT prove
  attribution.** Two indicators appearing together may share infrastructure,
  be reused by multiple actors, or coincide by chance.
* Timing overlap, shared categories and campaign IDs raise analytical
  confidence but can never, alone, identify the adversary.
* Attribution (who is behind it) requires evidence far beyond IOC
  clusters — and is deliberately out of scope for this project.

## The five-concept discipline (what this dashboard enforces)

| Concept | Meaning | Not to be confused with |
|---|---|---|
| OBSERVATION | one raw sighting | a verdict |
| INDICATOR | validated artifact | proof of compromise |
| ALERT | triage cue | an incident |
| THREAT | assessed record | an attack in progress |
| INCIDENT | **confirmed** event | anything automated |

And the two-score discipline: **Risk** (how concerning) vs **Confidence**
(how well evidenced). High risk with low confidence is a prompt to
investigate — not permission to panic or to auto-block.

## What this dashboard does about all this

1. **Separate risk and confidence** with explainable factor breakdowns.
2. **Mask/limit conclusions** — UI copy repeatedly states "IOC match ≠
   automatic confirmed compromise".
3. **FALSE_POSITIVE status** exists for threats AND alerts, and the
   timeline documents the decision (a first-class outcome, not an error).
4. **Staleness penalties** in confidence scoring (old last-seen reduces
   confidence).
5. **Correlation labeled as evidence** — attribution disclaimers on every
   cluster view.
6. **ATT&CK mapping only when justified** — insufficient context stays
   unmapped instead of guessed.
7. **Analyst notes and human decision points** at every step — automation
   proposes, humans dispose.

## Working rules for using any TI platform

1. Prefer **behavioural** evidence over single atomic indicators.
2. Check indicator age before acting.
3. Corroborate across independent sources.
4. Consider benign explanations first (shared infra, scanners, marketing).
5. Use blocks/rule changes with the smallest necessary scope and a review
   date.
6. Document false positives so detection improves.
