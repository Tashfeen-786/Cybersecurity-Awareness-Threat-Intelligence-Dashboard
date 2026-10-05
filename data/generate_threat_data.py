"""
Synthetic Threat-Intelligence Dataset Generator
===============================================

Generates TWO safe, fully-synthetic datasets for the
Cybersecurity Awareness & Threat Intelligence Dashboard:

    1. data/threat_intelligence_dataset.csv  (2,200+ threat records)
    2. data/vulnerabilities.csv              (60 synthetic CVE records)

SAFETY BY DESIGN (defensive-security requirements)
--------------------------------------------------
* IP addresses   -> ONLY the RFC 5737 documentation ranges
                    192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
* IPv6 addresses -> ONLY the RFC 3849 documentation prefix 2001:db8::/32
* Domains        -> ONLY example.com / example.org / example.net (RFC 2606)
                    and *.invalid (reserved, can never resolve)
* URLs           -> fictional paths on those safe domains only
* File hashes    -> random synthetic hex strings (not real malware hashes)
* CVE IDs        -> synthetic CVE-YYYY-9NNNNN identifiers that follow the
                    CVE format but do NOT exist in any real advisory
* Everything is labelled "SYNTHETIC / DEMO ONLY"

NO network access is performed by this generator. It never contacts,
resolves, visits or queries any indicator. It only WRITES local CSV files.

Risk and confidence scores are computed with the SAME engines the backend
uses (backend/services/risk_engine.py), so the dataset is consistent and
explainable. A fixed random seed keeps regeneration deterministic.

The PDF's required demonstration scenario is pinned exactly:

    THR-2026-001 "Synthetic Credential Phishing Campaign"
      DOMAIN login-check.invalid | HIGH | risk 78 | confidence 85
      status MONITORING | related indicator 198.51.100.25
"""
from __future__ import annotations

import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the backend services importable when run from any working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from services.risk_engine import (  # noqa: E402
    calculate_confidence,
    calculate_threat_risk,
)
from services.attack_mapper import get_mapping_for_record  # noqa: E402
from services.vulnerability_service import (  # noqa: E402
    calculate_vulnerability_priority,
    cvss_severity,
)

DATA_DIR = Path(__file__).resolve().parent

SEED = 20260930                # fixed seed -> deterministic regeneration
TOTAL_RECORDS = 2200           # spec requires at least 2,000
TOTAL_VULNERABILITIES = 60
SYNTHETIC_LABEL = "SYNTHETIC / DEMO ONLY"

# ---------------------------------------------------------------------------
# Safe indicator pools (documentation/reserved values ONLY)
# ---------------------------------------------------------------------------
DOC_IPV4_PREFIXES = ["192.0.2.", "198.51.100.", "203.0.113."]   # RFC 5737
DOC_IPV6_PREFIX = "2001:db8:"                                    # RFC 3849

DOMAIN_BASES = ["example.com", "example.org", "example.net",    # RFC 2606
                "demo.invalid", "mail.invalid", "portal.invalid",
                "secure.invalid", "login.invalid", "updates.invalid",
                "support.invalid", "billing.invalid", "auth.invalid"]

DOMAIN_WORDS = [
    "login", "verify", "secure", "portal", "account", "billing", "support",
    "update", "password", "signin", "helpdesk", "hr-notice", "invoice",
    "payment", "document", "mail", "notify", "service", "portal-verify",
    "team-share", "cloud-backup", "wire-transfer", "docusign-view",
]

URL_PATHS = [
    "verify-account.html", "secure/login", "update-password", "login",
    "portal/verify", "invoice/view.html", "document.html", "auth/check",
    "account/confirm", "secure-update/payment", "team/share",
    "password-reset/verify", "attachment/invoice-2026.zip.html",
]

HASH_KINDS = [("sha256", 64), ("sha256", 64), ("sha256", 64),
              ("sha1", 40), ("md5", 32)]

CATEGORIES = [
    "Phishing", "Malware", "Ransomware", "Credential Theft", "Web Threats",
    "Network Threats", "Vulnerability Exposure", "Social Engineering",
    "Data Exposure", "Account Security",
]
CATEGORY_WEIGHTS = [22, 14, 9, 10, 9, 9, 8, 8, 6, 5]

SOURCES = {
    # source_name -> reliability grade (see backend/services/risk_engine.py)
    "Internal SOC": "A",
    "Security Vendor": "B",
    "Public Threat Feed": "C",
    "Research Report": "B",
    "Community Submission": "C",
    "Unknown Source": "D",
}
SOURCE_WEIGHTS = [("Internal SOC", 20), ("Security Vendor", 25),
                  ("Public Threat Feed", 20), ("Research Report", 15),
                  ("Community Submission", 15), ("Unknown Source", 5)]

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHTS = [10, 24, 28, 26, 12]

STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
STATUS_WEIGHTS = [20, 15, 35, 20, 10]

REGIONS = ["Global", "North America", "Europe", "Asia-Pacific",
           "Latin America", "Middle East & Africa", "", "Unknown"]

# ---------------------------------------------------------------------------
# Threat-name and description templates.
# "rich" descriptions carry behavioural context keywords which the ATT&CK
# mapper uses to justify a mapping; "generic" ones intentionally do NOT,
# demonstrating that mapping is omitted when evidence is insufficient.
# ---------------------------------------------------------------------------
NAME_TEMPLATES = {
    "Phishing": ["Synthetic Phishing Lure Domain", "Demo Credential Phishing Observation",
                 "Synthetic Phishing Infrastructure Sighting", "Synthetic Lookalike Domain Alert",
                 "Demo Phishing Campaign Indicator", "Synthetic Fake Portal Domain"],
    "Malware": ["Synthetic Malware Sample Hash", "Demo Downloader Hash Observation",
                "Synthetic Loader Hash Sighting", "Demo Malware Distribution Observation",
                "Synthetic Trojan Hash Indicator", "Synthetic Backdoor Beacon Observation"],
    "Ransomware": ["Synthetic Ransomware Sample", "Demo Ransomware Payload Hash",
                   "Synthetic Ransomware Note Indicator", "Demo Ransomware C2 Observation"],
    "Credential Theft": ["Synthetic Credential Stuffing Observation", "Demo Brute Force Activity",
                         "Synthetic Credential Harvester Sighting", "Demo Password Spray Observation"],
    "Web Threats": ["Synthetic Web Injection Observation", "Demo SQL Injection Attempt Indicator",
                    "Synthetic Exploit Kit Domain", "Demo Drive-by Download Serving Domain"],
    "Network Threats": ["Synthetic C2 Callback Observation", "Demo Port Scan Activity Indicator",
                        "Synthetic Beaconing Host Indicator", "Demo Tor Proxy Exit Observation"],
    "Vulnerability Exposure": ["Synthetic Vulnerability Exposure Record", "Demo Unpatched Service Indicator",
                               "Synthetic Exploitable Service Observation"],
    "Social Engineering": ["Synthetic Impersonation Attempt", "Demo Vishing Campaign Indicator",
                           "Synthetic CEO Fraud Domain", "Demo SMiShing Sender Observation"],
    "Data Exposure": ["Synthetic Data Leak Observation", "Demo Exfiltration Endpoint Indicator",
                      "Synthetic Public Leak Domain Sighting"],
    "Account Security": ["Synthetic Account Takeover Risk Indicator", "Demo Abnormal Login Pattern Observation",
                         "Synthetic Fraudulent Account Creation Indicator"],
}

RICH_DESCRIPTIONS = {
    "Phishing": [
        "Synthetic phishing lure domain observed in demo telemetry; the domain mimics a login verification portal. Indicator is analysed as data only - never visited. {label}",
        "Synthetic credential-phishing URL observed sending users to a fake account verification page in demo logs. {label}",
        "Synthetic e-mail attachment campaign observed in demo telemetry distributing phishing documents with credential harvest links. {label}",
    ],
    "Malware": [
        "Synthetic malware hash observed in demo telemetry; sample behaves as a downloader that executes an obfuscated payload and establishes C2 callback traffic. {label}",
        "Synthetic trojan hash sighted in demo data; associated with credential dumping behaviour in the sandbox report. {label}",
    ],
    "Ransomware": [
        "Synthetic ransomware sample observed in demo telemetry; the sample attempts file encryption of user documents and inhibits system recovery options. {label}",
        "Synthetic ransomware indicator observed in demo data; associated with service stop behaviour prior to encryption and data extortion staging. {label}",
    ],
    "Credential Theft": [
        "Synthetic credential stuffing activity observed in demo telemetry; high volume of brute force attempts against login endpoints from shared infrastructure. {label}",
        "Synthetic credential-harvesting page observed in demo telemetry; the page mimics a password store sign-in form. {label}",
    ],
    "Web Threats": [
        "Synthetic web attack indicator observed in demo telemetry; exploitation attempts against a public-facing application were recorded in demo logs. {label}",
        "Synthetic drive-by domain observed in demo data; client browser exploitation behaviour was simulated. {label}",
    ],
    "Network Threats": [
        "Synthetic command-and-control channel observed in demo telemetry; host beacon traffic to a C2 endpoint was recorded. {label}",
        "Synthetic scanning behaviour observed in demo data; network service scan attempts were logged from this address. {label}",
    ],
    "Vulnerability Exposure": [
        "Synthetic vulnerability exposure record; demo asset inventory shows an unpatched public-facing service with a known exploit path. Defensive awareness only. {label}",
        "Synthetic exploitable service observation; demo scanning metadata indicates exposure requiring patch review. {label}",
    ],
    "Social Engineering": [
        "Synthetic voice-phishing (vishing) attempt observed in demo telemetry; impersonation of the IT helpdesk was reported. {label}",
        "Synthetic SMiShing campaign indicator observed in demo data; messages impersonate a delivery service with a QR code lure. {label}",
    ],
    "Data Exposure": [
        "Synthetic exfiltration observation in demo telemetry; large outbound transfer attempts to an external endpoint were recorded. {label}",
        "Synthetic e-mail collection behaviour observed in demo data; mailbox export activity was simulated. {label}",
    ],
    "Account Security": [
        "Synthetic account takeover risk indicator; demo telemetry shows compromised valid accounts used from unusual locations. {label}",
        "Synthetic fraudulent account creation observed in demo telemetry; a new account was created outside standard process. {label}",
    ],
}

GENERIC_DESCRIPTIONS = {
    "Phishing": "Synthetic indicator of possible phishing relevance observed in demo telemetry. Insufficient behavioural context for further classification. {label}",
    "Malware": "Synthetic hash observed in demo telemetry. No behavioural report is available, so classification remains general. {label}",
    "Ransomware": "Synthetic indicator tentatively associated with ransomware activity in demo data. Behavioural context is not yet available. {label}",
    "Credential Theft": "Synthetic indicator observed during credential-abuse monitoring in demo telemetry. Context is limited. {label}",
    "Web Threats": "Synthetic indicator observed in web-monitoring demo data. No specific technique context available. {label}",
    "Network Threats": "Synthetic network indicator recorded in demo telemetry. Limited contextual evidence. {label}",
    "Vulnerability Exposure": "Synthetic vulnerability-related indicator from demo asset review. Detailed context pending. {label}",
    "Social Engineering": "Synthetic indicator reported through the demo social-engineering reporting channel. Context is limited. {label}",
    "Data Exposure": "Synthetic indicator associated with possible data-exposure monitoring in demo data. Context is limited. {label}",
    "Account Security": "Synthetic indicator from demo account-monitoring telemetry. Context is limited. {label}",
}

# ---------------------------------------------------------------------------
# Safe indicator factories
# ---------------------------------------------------------------------------
_rng = random.Random(SEED)


def random_ipv4() -> str:
    return _rng.choice(DOC_IPV4_PREFIXES) + str(_rng.randint(1, 254))


def random_ipv6() -> str:
    return (f"2001:db8:{_rng.randint(0x100, 0xfff):x}:"
            f"::{_rng.randint(1, 9999)}")


def random_domain() -> str:
    if _rng.random() < 0.35:
        return _rng.choice(DOMAIN_BASES)
    return f"{_rng.choice(DOMAIN_WORDS)}.{_rng.choice(DOMAIN_BASES)}"


def random_url() -> str:
    return f"{_rng.choice(['http://', 'https://'])}{random_domain()}/{_rng.choice(URL_PATHS)}"


def random_hash() -> str:
    import secrets
    _kind, length = _rng.choice(HASH_KINDS)
    return secrets.token_hex(length // 2)


def make_indicator(category: str):
    """Pick a (coarse_type, value, fine_hint) tuple for a category."""
    roll = _rng.random()
    if category == "Vulnerability Exposure" and roll < 0.55:
        return ("CVE ID", _rng.choice(_synthetic_cve_ids), "cve")
    if category in ("Phishing", "Social Engineering"):
        if roll < 0.40:
            return ("DOMAIN", random_domain(), "domain")
        if roll < 0.62:
            return ("URL", random_url(), "url")
        if roll < 0.80:
            return ("EMAIL DOMAIN", random_domain(), "email_domain")
        if roll < 0.90:
            return ("IP ADDRESS", random_ipv4(), "ipv4")
        return ("FILE HASH", random_hash(), "hash")
    if category in ("Malware", "Ransomware"):
        if roll < 0.65:
            return ("FILE HASH", random_hash(), "hash")
        if roll < 0.85:
            return ("IP ADDRESS", random_ipv4(), "ipv4")
        if roll < 0.95:
            return ("DOMAIN", random_domain(), "domain")
        return ("URL", random_url(), "url")
    if category in ("Web Threats", "Network Threats"):
        if roll < 0.45:
            return ("IP ADDRESS", random_ipv4(), "ipv4")
        if roll < 0.75:
            return ("DOMAIN", random_domain(), "domain")
        if roll < 0.90:
            return ("URL", random_url(), "url")
        return ("IP ADDRESS", random_ipv6(), "ipv6")
    if category == "Data Exposure":
        if roll < 0.45:
            return ("DOMAIN", random_domain(), "domain")
        if roll < 0.75:
            return ("URL", random_url(), "url")
        return ("IP ADDRESS", random_ipv4(), "ipv4")
    if category == "Account Security":
        if roll < 0.50:
            return ("IP ADDRESS", random_ipv4(), "ipv4")
        if roll < 0.80:
            return ("EMAIL DOMAIN", random_domain(), "email_domain")
        return ("DOMAIN", random_domain(), "domain")
    # Credential Theft
    if roll < 0.45:
        return ("IP ADDRESS", random_ipv4(), "ipv4")
    if roll < 0.80:
        return ("DOMAIN", random_domain(), "domain")
    return ("URL", random_url(), "url")


def weighted_choice(pairs):
    total = sum(weight for _, weight in pairs)
    roll = _rng.uniform(0, total)
    upto = 0
    for value, weight in pairs:
        upto += weight
        if roll <= upto:
            return value
    return pairs[-1][0]


# ---------------------------------------------------------------------------
# Synthetic CVE pool (format-valid but fictional; 9xxxxx sequence is
# deliberately far beyond real-world CVE sequence numbers)
# ---------------------------------------------------------------------------
def build_cve_pool() -> list:
    return [f"CVE-{year}-9{seq:05d}"
            for year in (2024, 2025, 2026)
            for seq in range(1, 31)]


_synthetic_cve_ids = build_cve_pool()

PRODUCT_CATEGORIES = [
    "Web Server", "VPN Gateway", "Email Gateway", "CMS Platform",
    "Database Server", "Office Suite", "Web Browser", "OS Kernel",
    "Network Appliance", "Backup Software", "Cloud Storage CLI",
    "Remote Monitoring Tool", "Printer Firmware", "IoT Camera Firmware",
    "File Transfer Appliance", "Identity Management Platform",
    "Virtualization Platform", "API Gateway", "HR Management Software",
    "E-commerce Platform",
]

PRODUCT_NAMES = {
    "Web Server": "HyperServe Web Server", "VPN Gateway": "SecureLink VPN Gateway",
    "Email Gateway": "MailGuard Email Gateway", "CMS Platform": "PageForge CMS",
    "Database Server": "DataCore RDBMS", "Office Suite": "OfficeWorks Suite",
    "Web Browser": "Nova Browser", "OS Kernel": "CoreBase Operating System",
    "Network Appliance": "NetFlow Router OS", "Backup Software": "SafeVault Backup",
    "Cloud Storage CLI": "CloudBucket CLI", "Remote Monitoring Tool": "WatchTower RMM",
    "Printer Firmware": "PrintMax Firmware", "IoT Camera Firmware": "SecureCam Firmware",
    "File Transfer Appliance": "SwiftShare File Transfer", "Identity Management Platform": "Identra IAM",
    "Virtualization Platform": "VirtSphere Hypervisor", "API Gateway": "GateKeep API Gateway",
    "HR Management Software": "PeopleOps HRMS", "E-commerce Platform": "ShopStream Commerce",
}

VULN_TITLES = [
    "Unauthenticated remote code execution in request parser",
    "SQL injection in administrative search endpoint",
    "Path traversal in file upload handler",
    "Server-side request forgery in webhook feature",
    "Improper authentication in session validation",
    "Heap-based buffer overflow in image decoder",
    "Reflected cross-site scripting in error page",
    "Insecure deserialization of configuration data",
    "Privilege escalation via improper authorization check",
    "Hard-coded credentials in management interface",
    "Command injection in diagnostic endpoint",
    "XML external entity injection in import function",
    "Race condition in password reset workflow",
    "Information disclosure in debug logging mode",
    "Improper certificate validation in update channel",
    "Use-after-free in media parsing component",
    "Blind SSRF in URL preview feature",
    "Weak default cryptography in token generation",
]


def generate_vulnerabilities(path: Path) -> int:
    """Generate data/vulnerabilities.csv (contextual fields included)."""
    rows = []
    used = set()
    for i in range(TOTAL_VULNERABILITIES):
        cve_id = _synthetic_cve_ids[i]
        used.add(cve_id)
        product_category = _rng.choice(PRODUCT_CATEGORIES)
        cvss = round(_rng.uniform(3.1, 10.0), 1)
        exposure = weighted_choice([("Internet-facing", 30), ("DMZ", 15),
                                    ("VPN-only", 15), ("Internal network", 25),
                                    ("Isolated lab", 15)])
        exploitation = weighted_choice([
            ("Active exploitation observed (synthetic)", 15),
            ("Proof-of-concept reported (synthetic)", 30),
            ("No known exploitation (synthetic)", 55)])
        business = weighted_choice([
            ("Mission-critical production", 25),
            ("Business-important production", 30),
            ("Standard internal service", 30),
            ("Non-production / test", 15)])
        criticality = _rng.randint(1, 5)
        patch = _rng.random() < 0.70
        title = _rng.choice(VULN_TITLES)
        published = (datetime.now(timezone.utc)
                     - timedelta(days=_rng.randint(20, 700))).date().isoformat()
        priority = calculate_vulnerability_priority(
            cvss, criticality, exposure, exploitation, business, patch)
        rows.append({
            "cve_id": cve_id,
            "product_category": product_category,
            "product_name": PRODUCT_NAMES[product_category],
            "severity": cvss_severity(cvss),
            "cvss_score": cvss,
            "published_date": published,
            "patch_available": str(bool(patch)),
            "exploitation_status_demo": exploitation,
            "asset_criticality": criticality,
            "exposure": exposure,
            "business_context": business,
            "priority_score": priority["priority_score"],
            "priority_band": priority["priority_band"],
            "description": (f"[{SYNTHETIC_LABEL}] Synthetic vulnerability record "
                            f"for defensive awareness: {title} affecting "
                            f"{PRODUCT_NAMES[product_category]}. No exploitation "
                            f"instructions included."),
        })

    # Pin the teaching example required by the project brief:
    #   Critical CVSS on an isolated test asset  (lower contextual priority)
    #   vs High CVSS on an internet-facing mission-critical system (highest)
    rows[0] = {
        "cve_id": "CVE-2026-900001",
        "product_category": "HR Management Software",
        "product_name": PRODUCT_NAMES["HR Management Software"],
        "severity": "CRITICAL", "cvss_score": 9.8,
        "published_date": (datetime.now(timezone.utc) - timedelta(days=90)).date().isoformat(),
        "patch_available": "True",
        "exploitation_status_demo": "No known exploitation (synthetic)",
        "asset_criticality": 2, "exposure": "Isolated lab",
        "business_context": "Non-production / test",
        "priority_score": None, "priority_band": None,
        "description": ("[SYNTHETIC / DEMO ONLY] Teaching example A: CRITICAL "
                        "CVSS 9.8, but the affected HR tool runs only on an "
                        "isolated lab asset with no exploitation evidence - "
                        "contextual priority is lower than raw CVSS suggests."),
    }
    rows[1] = {
        "cve_id": "CVE-2026-900002",
        "product_category": "VPN Gateway",
        "product_name": PRODUCT_NAMES["VPN Gateway"],
        "severity": "HIGH", "cvss_score": 8.1,
        "published_date": (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat(),
        "patch_available": "True",
        "exploitation_status_demo": "Active exploitation observed (synthetic)",
        "asset_criticality": 5, "exposure": "Internet-facing",
        "business_context": "Mission-critical production",
        "priority_score": None, "priority_band": None,
        "description": ("[SYNTHETIC / DEMO ONLY] Teaching example B: HIGH CVSS "
                        "8.1 on an internet-facing, mission-critical VPN "
                        "gateway with active exploitation evidence - "
                        "contextual priority exceeds the higher-CVSS lab issue."),
    }
    for row in rows:
        if row["priority_score"] is None:
            priority = calculate_vulnerability_priority(
                row["cvss_score"], row["asset_criticality"], row["exposure"],
                row["exploitation_status_demo"], row["business_context"],
                row["patch_available"] == "True")
            row["priority_score"] = priority["priority_score"]
            row["priority_band"] = priority["priority_band"]

    fieldnames = ["cve_id", "product_category", "product_name", "severity",
                  "cvss_score", "published_date", "patch_available",
                  "exploitation_status_demo", "asset_criticality", "exposure",
                  "business_context", "priority_score", "priority_band",
                  "description"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


# ---------------------------------------------------------------------------
# Threat record generation
# ---------------------------------------------------------------------------
def build_demo_campaign(now: datetime) -> list:
    """
    The PDF's required safe demonstration scenario, pinned exactly:

        THR-2026-001 Synthetic Credential Phishing Campaign
        DOMAIN login-check.invalid | PHISHING | HIGH
        risk 78/100 | confidence 85/100 | MONITORING
        related indicator 198.51.100.25

    The exact factor inputs (severity HIGH, confidence 85, last seen 15 days
    before the reference date, 3 observations, source reliability B, full
    correlation context) make calculate_threat_risk() return exactly 78 -
    verified by automated test T-013b.
    """
    campaign = "SYN-CAMP-2026-001"
    first_seen = now - timedelta(days=30)
    last_seen = now - timedelta(days=15)

    def rec(n, name, category, itype, value, source, status, obs, desc,
            days_offset_last=15, severity="HIGH"):
        risk = calculate_threat_risk(
            severity=severity, confidence=None, last_seen=None,
            observation_count=obs, source_reliability=None,
            context_flags=None, reference_now=None)
        return None  # placeholder - replaced below

    # Explicit construction (clearer than loops for a pinned scenario):
    def mk(threat_num, name, category, itype, value, source, status, obs,
           description, conf):
        risk = calculate_threat_risk(
            severity="HIGH",
            confidence=conf,
            last_seen=last_seen,
            observation_count=obs,
            source_reliability=SOURCES[source],
            context_flags={"correlated_cluster": True,
                           "related_indicator": True},
            reference_now=now,
        )
        return {
            "threat_id": f"THR-2026-{threat_num:03d}",
            "timestamp": last_seen,
            "threat_name": name,
            "threat_category": category,
            "indicator_type": itype,
            "indicator_value": value,
            "source_name": source,
            "confidence_score": conf,
            "severity": "HIGH",
            "risk_score": risk["risk_score"],
            "status": status,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "country_or_region_optional": "Global",
            "description": description,
            "mitre_tactic_optional": "",
            "mitre_technique_optional": "",
            "cve_id_optional": "",
            "campaign_id": campaign,
            "observation_count": obs,
        }

    demo = []
    # --- the pinned demonstration record ---------------------------------
    d1 = mk(1, "Synthetic Credential Phishing Campaign", "Phishing",
            "DOMAIN", "login-check.invalid", "Security Vendor", "MONITORING",
            3,
            "Synthetic credential-phishing lure domain observed in demo "
            "telemetry; mimics a login verification portal. SYNTHETIC / DEMO "
            "ONLY - fictional indicator for defensive training. Never visit "
            "this domain.", 85)
    assert d1["risk_score"] == 78, f"demo risk must be 78, got {d1['risk_score']}"
    demo.append(d1)

    # --- related infrastructure (same campaign) ---------------------------
    d2 = mk(2, "Synthetic Phishing Infrastructure IP", "Phishing",
            "IP ADDRESS", "198.51.100.25", "Security Vendor", "MONITORING", 3,
            "Synthetic hosting IP observed serving a phishing lure page in "
            "demo telemetry. SYNTHETIC / DEMO ONLY - documentation-range "
            "address, never contacted.", 85)
    assert d2["risk_score"] == 78, f"related IP risk must be 78, got {d2['risk_score']}"
    demo.append(d2)

    d3 = mk(3, "Synthetic Phishing Payload Hash", "Phishing",
            "FILE HASH", "a1b2c3d4e5f60718293a4b5c6d7e8f90"
            "a1b2c3d4e5f60718293a4b5c6d7e8f90", "Research Report",
            "UNDER_REVIEW", 2,
            "Synthetic attachment hash observed in a demo phishing document "
            "campaign. SYNTHETIC / DEMO ONLY - random synthetic hash, never "
            "executed or looked up online.", 70)
    demo.append(d3)

    d4 = mk(4, "Synthetic Phishing Lure Corroboration", "Phishing",
            "DOMAIN", "login-check.invalid", "Public Threat Feed",
            "MONITORING", 4,
            "Corroborating observation of the synthetic phishing lure domain "
            "from a second demo feed. SYNTHETIC / DEMO ONLY.", 80)
    demo.append(d4)

    d5 = mk(5, "Synthetic Phishing Lure Internal Sighting", "Phishing",
            "DOMAIN", "login-check.invalid", "Internal SOC", "MONITORING", 5,
            "Internal demo e-mail gateway sighting of the synthetic phishing "
            "lure domain. SYNTHETIC / DEMO ONLY.", 90)
    demo.append(d5)

    d6 = mk(6, "Synthetic Phishing Host IP Corroboration", "Phishing",
            "IP ADDRESS", "198.51.100.25", "Internal SOC", "MONITORING", 4,
            "Corroborating internal demo sighting of the synthetic phishing "
            "host IP. SYNTHETIC / DEMO ONLY - documentation-range address.",
            90)
    demo.append(d6)

    d7 = mk(7, "Synthetic Phishing Lure URL", "Phishing",
            "URL", "https://login-check.invalid/verify-account.html",
            "Research Report", "NEW", 2,
            "Synthetic phishing lure URL observed in demo telemetry; link "
            "leads to a fake account verification page. SYNTHETIC / DEMO "
            "ONLY - never visited or fetched by this application.", 70)
    demo.append(d7)

    d8 = mk(8, "Synthetic Phishing Host IP Feed Sighting", "Phishing",
            "IP ADDRESS", "198.51.100.25", "Public Threat Feed", "MONITORING",
            3,
            "Third demo feed sighting of the synthetic phishing host IP. "
            "SYNTHETIC / DEMO ONLY.", 80)
    demo.append(d8)
    return demo


def generate_campaign(now: datetime, index: int, used_domains: set) -> list:
    """Build one synthetic campaign cluster (2-6 related records)."""
    campaign_id = f"SYN-CAMP-{_rng.randint(1000, 9999)}-{index:03d}"
    category = weighted_choice(list(zip(CATEGORIES, CATEGORY_WEIGHTS)))
    anchor = now - timedelta(days=_rng.randint(3, 700))
    members = _rng.randint(2, 6)

    # Campaign indicator pool: 1-3 distinct values, some shared by members
    # (shared values = corroboration, distinct values = related indicators).
    pool = []
    for _ in range(_rng.randint(1, 3)):
        itype, value, _hint = make_indicator(category)
        if itype in ("DOMAIN", "URL", "EMAIL DOMAIN"):
            tries = 0
            while value in used_domains and tries < 10:
                itype, value, _hint = make_indicator(category)
                tries += 1
            used_domains.add(value)
        pool.append((itype, value))

    records = []
    for _ in range(members):
        itype, value = _rng.choice(pool)
        source = weighted_choice(SOURCE_WEIGHTS)
        days_back_first = _rng.randint(0, 10)
        first = anchor - timedelta(days=days_back_first)
        last = first + timedelta(days=_rng.randint(0, 12))
        if last > now:
            last = now
        obs = _rng.randint(1, 12)
        severity = weighted_choice(list(zip(SEVERITIES, SEVERITY_WEIGHTS)))
        status = weighted_choice(list(zip(STATUSES, STATUS_WEIGHTS)))
        rich = _rng.random() < 0.80          # campaigns usually carry context
        records.append({
            "threat_id": None,               # assigned later
            "timestamp": last,
            "threat_name": _rng.choice(NAME_TEMPLATES[category]),
            "threat_category": category,
            "indicator_type": itype,
            "indicator_value": value,
            "source_name": source,
            "confidence_score": None,        # computed in pass 2
            "severity": severity,
            "risk_score": None,              # computed in pass 2
            "status": status,
            "first_seen": first,
            "last_seen": last,
            "country_or_region_optional": _rng.choice(REGIONS),
            "description": (
                _rng.choice(RICH_DESCRIPTIONS[category]) if rich
                else GENERIC_DESCRIPTIONS[category]
            ).replace("{label}", ""),
            "mitre_tactic_optional": "",
            "mitre_technique_optional": "",
            "cve_id_optional": "",
            "campaign_id": campaign_id,
            "observation_count": obs,
        })
    return records


def generate_standalone(now: datetime, used_domains: set) -> dict:
    """Build a single standalone threat record."""
    category = weighted_choice(list(zip(CATEGORIES, CATEGORY_WEIGHTS)))
    itype, value, _hint = make_indicator(category)
    if itype in ("DOMAIN", "URL", "EMAIL DOMAIN"):
        tries = 0
        while value in used_domains and tries < 10:
            itype, value, _hint = make_indicator(category)
            tries += 1
        used_domains.add(value)

    first = now - timedelta(days=_rng.randint(1, 700))
    last = first + timedelta(days=_rng.randint(0, 30))
    if last > now:
        last = now
    return {
        "threat_id": None,
        "timestamp": last,
        "threat_name": _rng.choice(NAME_TEMPLATES[category]),
        "threat_category": category,
        "indicator_type": itype,
        "indicator_value": value,
        "source_name": weighted_choice(SOURCE_WEIGHTS),
        "confidence_score": None,
        "severity": weighted_choice(list(zip(SEVERITIES, SEVERITY_WEIGHTS))),
        "risk_score": None,
        "status": weighted_choice(list(zip(STATUSES, STATUS_WEIGHTS))),
        "first_seen": first,
        "last_seen": last,
        "country_or_region_optional": _rng.choice(REGIONS),
        "description": (
            _rng.choice(RICH_DESCRIPTIONS[category]) if _rng.random() < 0.55
            else GENERIC_DESCRIPTIONS[category]
        ).replace("{label}", ""),
        "mitre_tactic_optional": "",
        "mitre_technique_optional": "",
        "cve_id_optional": "",
        "campaign_id": "",
        "observation_count": _rng.randint(1, 9),
    }


def assign_attck_mapping(record: dict) -> None:
    """
    Map to ATT&CK ONLY when the observation DESCRIPTION carries enough
    behavioural context. The threat NAME is deliberately NOT used as
    context: a name like "Phishing Observation" is a category label,
    not evidence of how the adversary behaved.
    """
    mapping = get_mapping_for_record(
        record["threat_category"], record["description"])
    if mapping["technique_id"]:
        record["mitre_tactic_optional"] = mapping["tactic"]
        record["mitre_technique_optional"] = (
            f"{mapping['technique_id']} ({mapping['technique']})")
    else:
        record["mitre_tactic_optional"] = ""
        record["mitre_technique_optional"] = ""


def link_cve(record: dict) -> None:
    """Attach a synthetic CVE reference where category justifies it."""
    if record["threat_category"] == "Vulnerability Exposure":
        if record["indicator_type"] != "CVE ID":
            record["cve_id_optional"] = _rng.choice(_synthetic_cve_ids)
        else:
            record["cve_id_optional"] = record["indicator_value"]
    elif record["threat_category"] in ("Malware", "Web Threats") and _rng.random() < 0.15:
        record["cve_id_optional"] = _rng.choice(_synthetic_cve_ids)


def main() -> None:
    now = datetime.now(timezone.utc)

    print("[1/5] Generating synthetic vulnerability dataset ...")
    vuln_count = generate_vulnerabilities(DATA_DIR / "vulnerabilities.csv")

    print("[2/5] Building demonstration campaign (THR-2026-001) ...")
    records = build_demo_campaign(now)

    print("[3/5] Generating campaigns and standalone observations ...")
    used_domains = {"login-check.invalid"}
    num_campaigns = 96
    for i in range(num_campaigns):
        records.extend(generate_campaign(now, i, used_domains))
    while len(records) < TOTAL_RECORDS:
        records.append(generate_standalone(now, used_domains))

    # ------------------------------------------------------------------
    # Pass 2: indicator statistics -> confidence -> risk -> ATT&CK -> CVE
    # ------------------------------------------------------------------
    print("[4/5] Computing confidence, risk scores and ATT&CK mapping ...")
    value_sources = {}      # indicator_value -> set(source names)
    value_counts = {}
    for rec in records:
        value_sources.setdefault(rec["indicator_value"], set()).add(
            rec["source_name"])
        value_counts[rec["indicator_value"]] = (
            value_counts.get(rec["indicator_value"], 0) + 1)

    campaign_values = {}
    for rec in records:
        if rec["campaign_id"]:
            campaign_values.setdefault(rec["campaign_id"], set()).add(
                rec["indicator_value"])

    counter = 0
    year_counters = {}
    for rec in records:
        counter += 1
        # Deterministic threat IDs: THR-<year of first observation>-<seq>
        year = rec["first_seen"].year
        year_counters[year] = year_counters.get(year, 0) + 1
        if not rec["threat_id"]:
            rec["threat_id"] = f"THR-{year}-{year_counters[year]:04d}"

        sources_for_value = len(value_sources[rec["indicator_value"]])
        conf = calculate_confidence(
            source_reliability=SOURCES[rec["source_name"]],
            corroborating_sources=sources_for_value,
            observation_count=rec["observation_count"],
            last_seen=rec["last_seen"],
            reference_now=now,
        )
        rec["confidence_score"] = conf["confidence_score"]

        in_campaign = bool(rec["campaign_id"])
        distinct_in_campaign = (len(campaign_values.get(rec["campaign_id"], set()))
                                if in_campaign else 0)
        context_flags = {
            "correlated_cluster": in_campaign
            or value_counts[rec["indicator_value"]] >= 2,
            "related_indicator": distinct_in_campaign >= 2,
        }
        risk = calculate_threat_risk(
            severity=rec["severity"],
            confidence=rec["confidence_score"],
            last_seen=rec["last_seen"],
            observation_count=rec["observation_count"],
            source_reliability=SOURCES[rec["source_name"]],
            context_flags=context_flags,
            reference_now=now,
        )
        rec["risk_score"] = risk["risk_score"]

        assign_attck_mapping(rec)
        link_cve(rec)

    # Keep the pinned demo record IDs stable at the top of the sequence:
    # (build_demo_campaign already set THR-2026-001..008 explicitly)

    # ------------------------------------------------------------------
    # Pass 3: write CSV
    # ------------------------------------------------------------------
    print("[5/5] Writing threat_intelligence_dataset.csv ...")
    fieldnames = [
        "threat_id", "timestamp", "threat_name", "threat_category",
        "indicator_type", "indicator_value", "source_name",
        "confidence_score", "severity", "risk_score", "status",
        "first_seen", "last_seen", "country_or_region_optional",
        "description", "mitre_tactic_optional", "mitre_technique_optional",
        "cve_id_optional", "campaign_id", "observation_count",
    ]
    out = DATA_DIR / "threat_intelligence_dataset.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            row = dict(rec)
            for key in ("timestamp", "first_seen", "last_seen"):
                row[key] = row[key].replace(microsecond=0).isoformat()
            writer.writerow(row)

    meta = {
        "generated_at": now.replace(microsecond=0).isoformat(),
        "seed": SEED,
        "record_count": len(records),
        "vulnerability_count": vuln_count,
        "demo_threat_id": "THR-2026-001",
        "safety_notice": (
            "All indicators are synthetic and use only documentation ranges "
            "(RFC 5737 / RFC 3849), example/invalid domains (RFC 2606), "
            "random synthetic hashes and fictional CVE-format IDs. "
            "SYNTHETIC / DEMO ONLY. No real, live or malicious indicators "
            "are included, and no indicator is ever contacted."
        ),
    }
    with open(DATA_DIR / "dataset_meta.json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    print(f"      Wrote {len(records)} threat records -> {out}")
    print(f"      Wrote {vuln_count} vulnerability records -> "
          f"{DATA_DIR / 'vulnerabilities.csv'}")
    print("      SYNTHETIC / DEMO ONLY - safe for educational use.")


if __name__ == "__main__":
    main()
