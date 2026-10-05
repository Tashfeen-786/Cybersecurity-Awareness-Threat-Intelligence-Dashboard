# Future Improvements (defensive only)

Every item below strengthens DEFENSE. Nothing here adds attack capability.

## Threat-intelligence ingestion
* **Authorized live threat-feed integration** — connect approved feeds
  (commercial or organizational) behind proper licensing and safety rules.
* **STIX/TAXII support** — consume/produce STIX 2.1 bundles; TAXII polling
  collections for machine-to-machine exchange.
* **Threat-feed deduplication** — cross-feed IOC dedupe with provenance
  tracking (same indicator, N sources).
* **IOC expiration & aging** — automatic confidence decay and expiry rules
  (e.g., downgrade after 90 days unseen), with archival.

## Scoring & analysis
* **Better confidence scoring** — weighted source reputations over time,
  per-feed historical accuracy, Bayesian updates as corroboration arrives.
* **Automated enrichment (authorized sources only)** — internal asset/CMDB
  joins, internal DNS/whois caches (pre-fetched, policy-approved).
* **Threat clustering** — graph clustering (shared infrastructure, timing,
  TTP overlap) to suggest campaigns for analyst confirmation.
* **IOC-to-asset context** — highlight indicators that actually touch
  internal assets.

## Vulnerability management
* **CVE feed integration** (e.g., NVD mirrors) and **CISA KEV awareness** —
  flag known-exploited vulnerabilities automatically.
* **EPSS-style prioritization** — probability-of-exploitation signals
  alongside CVSS and asset context.

## ATT&CK
* **ATT&CK Navigator layers** — export coverage/heat layers for detection
  gap analysis.
* **Detection coverage mapping** — show which techniques have detections.

## Operations
* **SIEM integration** — forward enriched alerts (Syslog/CEF/webhook) and
  ingest SIEM sightings to close the feedback loop.
* **SOAR integration** — playbooks for triage automation with human
  approval gates.
* **Email-security & endpoint telemetry integration** — correlate gateway
  blocks and EDR events with the intel dataset.
* **Cloud-security intelligence** — CSP-native signals (guard duty-style)
  joined with the threat DB.
* **Threat hunting workbench** — hypothesis tracking, saved queries, hunt
  libraries.
* **Advanced executive reporting** — scheduled PDF/HTML reports with trend
  deltas.
* **Role-based dashboards** — tailored views for SOC, IR, executives,
  awareness team.

## Platform engineering
* **Docker deployment** — container image + docker-compose (app + optional
  PostgreSQL).
* **CI/CD** — GitHub Actions running the test suite on every push.
* **Centralized logging** — structured app logs with retention policy.
* **PostgreSQL migration** — same schema, connection pooling, read replicas.
* **Redis rate limiting / caching** for multi-instance deployments.
