# Threat Categories Reference

The ten categories used across the dataset, dashboard and awareness content
(project-brief section 13). For every category: description, common
indicators, potential impact, defensive controls and awareness
recommendations. **No exploitation instructions — defensive documentation
only.**

---

## Phishing
* **Description:** Social-engineering messages (email/SMS/voice/QR) that
  impersonate trusted parties to steal credentials, deliver payloads or
  trick users into payments.
* **Common indicators:** lure domains and lookalike domains, phishing URLs,
  sender domains, attachment hashes.
* **Potential impact:** account takeover, credential theft, malware
  delivery, financial fraud.
* **Defensive controls:** email gateway filtering, URL sandboxing,
  DMARC/SPF/DKIM, report buttons, phishing-resistant MFA.
* **Awareness:** Phishing Awareness module (+ AI-Enabled Scam Awareness).

## Malware
* **Description:** Malicious software — loaders, trojans, backdoors,
  information stealers — delivered via attachments, drives-by downloads or
  bundled software.
* **Common indicators:** file hashes (SHA-256/SHA-1/MD5), C2 domains/IPs,
  dropper URLs.
* **Potential impact:** persistence, data theft, further staging, ransomware
  deployment.
* **Defensive controls:** EDR/AV with behaviour detection, application
  allow-listing, least privilege, patching, email security.
* **Awareness:** Safe Browsing, USB/Media Safety, Software Updates.

## Ransomware
* **Description:** Malware that denies access to systems/data (classically
  via encryption) and demands payment; modern variants add data-theft
  extortion.
* **Common indicators:** ransom-note hashes, encryption behaviour
  (IOA-style), C2 infrastructure, initial-access CVEs.
* **Potential impact:** file encryption, service disruption, data
  exposure/extortion, operational downtime.
* **Defensive controls:** tested offline backups, patching, least privilege,
  email security, endpoint protection, network segmentation, MFA,
  monitoring, IR preparation.
* **Awareness:** Ransomware Awareness module (defensive only).

## Credential Theft
* **Description:** Attacks that obtain account credentials — phishing,
  brute force/spraying/stuffing, credential dumping, theft from password
  stores.
* **Common indicators:** brute-force source IPs, credential-harvester
  domains, dumped-credential tool hashes.
* **Potential impact:** account takeover, lateral movement, data access.
* **Defensive controls:** MFA (phishing-resistant where possible), rate
  limiting/lockout, password managers, monitoring for impossible travel.
* **Awareness:** Password Security + MFA modules.

## Web Threats
* **Description:** Attacks against web applications and browsers —
  injection, exploitation of public-facing applications, drive-by
  frameworks, skimmers.
* **Common indicators:** exploit-kit domains, injection payloads, vulnerable
  endpoint URLs, associated CVEs.
* **Potential impact:** data breach, defacement, session/account compromise,
  client infection.
* **Defensive controls:** WAF, input validation, patching web stacks,
  CSP, dependency scanning.
* **Awareness:** Safe Browsing, Software Updates.

## Network Threats
* **Description:** Suspicious network-level activity — C2 channels, beaconing,
  scanning, tunneling/proxy abuse, DoS.
* **Common indicators:** C2 IPs/domains, scanning source IPs, unusual
  protocols/beacon patterns.
* **Potential impact:** command-and-control, exfiltration channel, service
  disruption, reconnaissance for later stages.
* **Defensive controls:** egress filtering, DNS security, flow analytics,
  IDS/IPS, segmentation.
* **Awareness:** Secure Wi-Fi, Remote Work Security.

## Vulnerability Exposure
* **Description:** Unpatched or misconfigured services creating exploitable
  exposure (tracked with CVE context and prioritization).
* **Common indicators:** CVE IDs, affected product/version, exposure
  metadata.
* **Potential impact:** initial access, ransomware entry, data theft.
* **Defensive controls:** risk-based patch management (CVSS + context),
  asset inventory, compensating controls, attack-surface management.
* **Awareness:** Software Updates module.

## Social Engineering
* **Description:** Manipulating people (impersonation, pretexting, vishing,
  SMiShing, tailgating, CEO fraud) to bypass process and controls.
* **Common indicators:** impersonation domains, reported caller IDs,
  fraudulent payment details.
* **Potential impact:** fraud, credential disclosure, physical access,
  process bypass.
* **Defensive controls:** verification procedures, out-of-band confirmation
  for payments, no-blame reporting culture.
* **Awareness:** Social Engineering + AI-Enabled Scam Awareness.

## Data Exposure
* **Description:** Sensitive data left accessible or leaving through
  unauthorized channels — leaks, misconfigured shares, exfiltration.
* **Common indicators:** exfiltration endpoints, leaked-data domains,
  unusual transfer volumes.
* **Potential impact:** regulatory/privacy harm, reputational damage,
  competitive loss.
* **Defensive controls:** DLP, access control, encryption, classification,
  egress monitoring.
* **Awareness:** Data Privacy module.

## Account Security
* **Description:** Risks to accounts themselves — takeover, fraudulent
  account creation, MFA fatigue, mail-forwarding persistence.
* **Common indicators:** takeover source IPs, suspicious sender domains,
  impossible-travel patterns.
* **Potential impact:** full account compromise, persistence, internal
  fraud.
* **Defensive controls:** MFA, conditional access, session monitoring,
  reviewing forwarding rules and new accounts.
* **Awareness:** MFA, Cloud Account Security, Mobile Security.
