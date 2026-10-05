"""
MITRE ATT&CK Mapping Service
============================

MITRE ATT&CK is a knowledge base of ADVERSARY BEHAVIOUR observed in real
cyber operations, organised into:

    TACTIC        - WHY an adversary performs an action (the objective,
                    e.g. Initial Access, Credential Access, Impact).
    TECHNIQUE     - HOW that objective may be achieved (e.g. Phishing).
    SUB-TECHNIQUE - a more specific implementation of a technique
                    (e.g. Spearphishing Link).

KEY CONCEPT IN THIS PROJECT
    An IOC tells us WHAT artifact was observed (domain, IP, hash...).
    ATT&CK helps describe HOW the observed behaviour MAY relate to
    adversary techniques.

MAPPING POLICY (defensive honesty)
    * Records are mapped ONLY when the synthetic observation carries
      enough behavioural context (e.g. a phishing lure domain implies
      the Phishing technique).
    * When evidence is insufficient, the record is left UNMAPPED and the
      UI explicitly says "Insufficient context for ATT&CK mapping".
    * We NEVER invent technique IDs. Only well-known, real technique IDs
      from the public ATT&CK knowledge base are used, and only with
      high-level synthetic behaviour descriptions.

References: https://attack.mitre.org/
"""
from __future__ import annotations

from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Curated ATT&CK reference (real, well-known technique IDs only)
# tactic -> {technique_id: technique_name}
# ---------------------------------------------------------------------------
ATTACK_REFERENCE: Dict[str, Dict[str, str]] = {
    "Reconnaissance": {
        "T1595": "Active Scanning",
        "T1592": "Gather Victim Host Information",
    },
    "Resource Development": {
        "T1583": "Acquire Infrastructure",
        "T1584": "Compromise Infrastructure",
        "T1587": "Develop Capabilities",
    },
    "Initial Access": {
        "T1566": "Phishing",
        "T1566.001": "Phishing: Spearphishing Attachment",
        "T1566.002": "Phishing: Spearphishing Link",
        "T1566.003": "Phishing: Spearphishing Voice",
        "T1190": "Exploit Public-Facing Application",
        "T1078": "Valid Accounts",
        "T1133": "External Remote Services",
    },
    "Execution": {
        "T1204": "User Execution",
        "T1204.002": "User Execution: Malicious File",
        "T1059": "Command and Scripting Interpreter",
        "T1203": "Exploitation for Client Execution",
    },
    "Persistence": {
        "T1136": "Create Account",
        "T1547.001": "Registry Run Keys / Startup Folder",
    },
    "Privilege Escalation": {
        "T1548.002": "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "T1068": "Exploitation for Privilege Escalation",
    },
    "Defense Evasion": {
        "T1027": "Obfuscated Files or Information",
        "T1055": "Process Injection",
        "T1078": "Valid Accounts",
    },
    "Credential Access": {
        "T1110": "Brute Force",
        "T1003": "OS Credential Dumping",
        "T1555": "Credentials from Password Stores",
        "T1566": "Phishing",
    },
    "Discovery": {
        "T1046": "Network Service Discovery",
        "T1087": "Account Discovery",
        "T1082": "System Information Discovery",
    },
    "Lateral Movement": {
        "T1021": "Remote Services",
        "T1072": "Software Deployment Tools",
    },
    "Collection": {
        "T1114": "Email Collection",
        "T1005": "Data from Local System",
    },
    "Command and Control": {
        "T1071": "Application Layer Protocol",
        "T1071.001": "Application Layer Protocol: Web Protocols",
        "T1105": "Ingress Tool Transfer",
        "T1090": "Proxy",
        "T1573": "Encrypted Channel",
    },
    "Exfiltration": {
        "T1041": "Exfiltration Over C2 Channel",
        "T1048": "Exfiltration Over Alternative Protocol",
    },
    "Impact": {
        "T1486": "Data Encrypted for Impact",
        "T1489": "Service Stop",
        "T1490": "Inhibit System Recovery",
        "T1485": "Data Destruction",
        "T1498": "Network Denial of Service",
    },
}

# Reverse lookup: technique_id -> (tactic, technique_name)
TECHNIQUE_INDEX = {
    tech_id: (tactic, tech_name)
    for tactic, techniques in ATTACK_REFERENCE.items()
    for tech_id, tech_name in techniques.items()
}

# ---------------------------------------------------------------------------
# Category -> justified mapping candidates.
# A category alone does NOT justify a technique; the generator only applies a
# mapping when the observation context (lure page, credential form, C2
# traffic description...) is present. This table lists the candidates and
# the required context keywords for honesty.
# ---------------------------------------------------------------------------
CATEGORY_MAPPING_CANDIDATES = {
    "Phishing": [
        {"tactic": "Initial Access", "technique_id": "T1566.002",
         "context_keywords": ["link", "lure", "url", "portal", "verify", "login"],
         "justification": "Phishing lure domain/URL observed in synthetic "
                          "credential-phishing campaign."},
        {"tactic": "Initial Access", "technique_id": "T1566.001",
         "context_keywords": ["attachment", "invoice", "document", "macro"],
         "justification": "Malicious e-mail attachment observed in synthetic "
                          "phishing campaign."},
        {"tactic": "Credential Access", "technique_id": "T1566",
         "context_keywords": ["credential", "password", "harvest"],
         "justification": "Credential-harvesting page observed (synthetic)."},
    ],
    "Malware": [
        {"tactic": "Execution", "technique_id": "T1204.002",
         "context_keywords": ["attachment", "download", "dropper", "execute"],
         "justification": "Malicious file execution observed in synthetic "
                          "malware observation."},
        {"tactic": "Command and Control", "technique_id": "T1071.001",
         "context_keywords": ["c2", "beacon", "callback", "traffic"],
         "justification": "Synthetic C2 callback traffic observed."},
        {"tactic": "Defense Evasion", "technique_id": "T1027",
         "context_keywords": ["obfuscated", "packed", "polymorphic"],
         "justification": "Obfuscated payload observed (synthetic)."},
    ],
    "Ransomware": [
        {"tactic": "Impact", "technique_id": "T1486",
         "context_keywords": ["encrypt", "encryption", "files"],
         "justification": "File-encryption behaviour observed in synthetic "
                          "ransomware sample."},
        {"tactic": "Impact", "technique_id": "T1490",
         "context_keywords": ["recovery", "backup", "shadow"],
         "justification": "Recovery-inhibition behaviour observed (synthetic)."},
        {"tactic": "Impact", "technique_id": "T1489",
         "context_keywords": ["service", "shutdown", "stop"],
         "justification": "Service-disruption behaviour observed (synthetic)."},
    ],
    "Credential Theft": [
        {"tactic": "Credential Access", "technique_id": "T1110",
         "context_keywords": ["brute", "spray", "stuffing", "attempts"],
         "justification": "Credential brute-force activity observed (synthetic)."},
        {"tactic": "Credential Access", "technique_id": "T1555",
         "context_keywords": ["store", "browser", "vault", "saved"],
         "justification": "Credential-store theft behaviour observed (synthetic)."},
        {"tactic": "Credential Access", "technique_id": "T1003",
         "context_keywords": ["dump", "lsass", "memory"],
         "justification": "Credential-dumping behaviour observed (synthetic)."},
    ],
    "Web Threats": [
        {"tactic": "Initial Access", "technique_id": "T1190",
         "context_keywords": ["exploit", "public-facing", "injection", "cve"],
         "justification": "Exploitation of public-facing application observed "
                          "(synthetic)."},
        {"tactic": "Execution", "technique_id": "T1203",
         "context_keywords": ["drive-by", "browser", "client"],
         "justification": "Client-side exploitation observed (synthetic)."},
    ],
    "Network Threats": [
        {"tactic": "Command and Control", "technique_id": "T1071",
         "context_keywords": ["c2", "channel", "callback", "traffic"],
         "justification": "Command-and-control channel observed (synthetic)."},
        {"tactic": "Command and Control", "technique_id": "T1090",
         "context_keywords": ["proxy", "relay", "tunnel"],
         "justification": "Proxy/tunnelling behaviour observed (synthetic)."},
        {"tactic": "Discovery", "technique_id": "T1046",
         "context_keywords": ["scan", "recon", "enumerat"],
         "justification": "Network service scanning observed (synthetic)."},
    ],
    "Vulnerability Exposure": [
        {"tactic": "Initial Access", "technique_id": "T1190",
         "context_keywords": ["exploit", "cve", "public-facing", "patch"],
         "justification": "Known exploitable vulnerability exposure observed "
                          "(synthetic, defensive awareness)."},
    ],
    "Social Engineering": [
        {"tactic": "Initial Access", "technique_id": "T1566.003",
         "context_keywords": ["voice", "call", "vish", "sms", "smsh", "qr"],
         "justification": "Voice/SMiShing social-engineering attempt observed "
                          "(synthetic)."},
        {"tactic": "Initial Access", "technique_id": "T1566",
         "context_keywords": ["impersonat", "pretext", "ceo", "fraud"],
         "justification": "Impersonation-based phishing observed (synthetic)."},
    ],
    "Data Exposure": [
        {"tactic": "Exfiltration", "technique_id": "T1048",
         "context_keywords": ["exfiltrat", "transfer", "upload", "leak"],
         "justification": "Data-exfiltration behaviour observed (synthetic)."},
        {"tactic": "Exfiltration", "technique_id": "T1041",
         "context_keywords": ["c2", "channel"],
         "justification": "Exfiltration over C2 channel observed (synthetic)."},
        {"tactic": "Collection", "technique_id": "T1114",
         "context_keywords": ["email", "mailbox", "collection"],
         "justification": "E-mail collection behaviour observed (synthetic)."},
    ],
    "Account Security": [
        {"tactic": "Persistence", "technique_id": "T1136",
         "context_keywords": ["account", "created", "new"],
         "justification": "Suspicious account creation observed (synthetic)."},
        {"tactic": "Initial Access", "technique_id": "T1078",
         "context_keywords": ["valid accounts", "compromised", "takeover"],
         "justification": "Abuse of valid accounts observed (synthetic)."},
    ],
}

# Sentinel used when a record has NO justified mapping.
UNMAPPED = {
    "tactic": None,
    "technique_id": None,
    "technique": None,
    "justification": "Insufficient behavioural context for ATT&CK mapping. "
                     "Mapping is intentionally omitted rather than guessed.",
}


def get_mapping_for_record(category: str, description: str,
                           indicator_context: str = "") -> Dict:
    """
    Decide whether a threat record has enough context to justify an
    ATT&CK mapping. Returns a dict:

        {tactic, technique_id, technique, justification}

    or the UNMAPPED sentinel when evidence is insufficient.
    """
    text = f"{description} {indicator_context}".lower()
    for candidate in CATEGORY_MAPPING_CANDIDATES.get(category, []):
        if any(kw in text for kw in candidate["context_keywords"]):
            technique_name = TECHNIQUE_INDEX.get(
                candidate["technique_id"], (None, candidate["technique_id"]))
            return {
                "tactic": candidate["tactic"],
                "technique_id": candidate["technique_id"],
                "technique": technique_name[1],
                "justification": candidate["justification"],
            }
    return dict(UNMAPPED)


def technique_label(technique_id: str) -> Optional[str]:
    """Return 'T1566.002 - Spearphishing Link' style labels."""
    entry = TECHNIQUE_INDEX.get(technique_id)
    if not entry:
        return None
    return f"{technique_id} - {entry[1]}"


def all_tactics() -> List[str]:
    """Ordered list of ATT&CK tactics in the curated reference."""
    return list(ATTACK_REFERENCE.keys())


def all_techniques() -> List[Dict]:
    """Flat list of {technique_id, technique, tactic} for browsing UIs."""
    return [
        {"technique_id": tech_id, "technique": name, "tactic": tactic}
        for tactic, techniques in ATTACK_REFERENCE.items()
        for tech_id, name in techniques.items()
    ]
