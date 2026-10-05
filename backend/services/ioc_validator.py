"""
IOC Validation Engine
=====================

``validate_indicator()`` answers exactly ONE question:

    "Is this string SYNTACTICALLY VALID for a known indicator type?"

It does NOT answer:
    * "Is this indicator malicious?"  -> that requires intelligence, not syntax.
    * "Is this system compromised?"   -> an IOC match is never automatic proof
                                         of compromise.

IMPORTANT (defensive requirement):
The validator never performs DNS lookups, never opens sockets and never
contacts any indicator. Validation is pure string/structure analysis,
so the whole project works fully offline. See tests/test_security.py which
blocks all sockets and proves no network call is attempted.

Supported types: IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256, CVE ID.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List
from urllib.parse import urlparse

# --- Regular expressions (compiled once) ------------------------------------
RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
RE_LABEL_SAFE = re.compile(r"^[A-Za-z0-9.:_/\-]+$")

# Canonical indicator type names used across the project
TYPE_IPV4 = "ipv4"
TYPE_IPV6 = "ipv6"
TYPE_DOMAIN = "domain"
TYPE_URL = "url"
TYPE_MD5 = "md5"
TYPE_SHA1 = "sha1"
TYPE_SHA256 = "sha256"
TYPE_CVE = "cve"
TYPE_FILE_HASH = "file_hash"          # coarse group for MD5/SHA1/SHA256
TYPE_EMAIL_DOMAIN = "email_domain"    # sender domain of an e-mail address
TYPE_UNKNOWN = "unknown"

HASH_TYPES = {TYPE_MD5: "MD5", TYPE_SHA1: "SHA-1", TYPE_SHA256: "SHA-256"}


def validate_indicator(raw_value: str) -> Dict:
    """
    Validate an indicator string syntactically.

    Returns a dict:
        {
          "valid": bool,
          "indicator_type": "ipv4" | "ipv6" | "domain" | "url" | "md5" |
                            "sha1" | "sha256" | "cve" | "unknown",
          "normalized_value": str,     # canonical form used for lookups
          "validation_notes": [str]    # human-readable, explainable notes
        }

    Notes always make clear that validity != maliciousness and that no
    network connection was made.
    """
    notes: List[str] = []
    if raw_value is None:
        return _result(False, TYPE_UNKNOWN, "", ["No indicator value supplied."])

    value = str(raw_value).strip()
    if not value:
        return _result(False, TYPE_UNKNOWN, "", ["Empty indicator value."])

    if len(value) > 2048:
        return _result(False, TYPE_UNKNOWN, value[:2048],
                       ["Indicator exceeds maximum length of 2048 characters."])

    # 1) CVE ID -------------------------------------------------------------
    if value.upper().startswith("CVE-"):
        if RE_CVE.match(value):
            normalized = value.upper()
            notes.append("Valid CVE ID format (CVE-YYYY-NNNN).")
            notes.append("Format validation only - this does not confirm the CVE exists.")
            return _result(True, TYPE_CVE, normalized, notes)
        notes.append("Invalid CVE format. Expected pattern: CVE-YYYY-NNNN "
                     "(e.g. CVE-2026-900001, a synthetic demo ID).")
        return _result(False, TYPE_CVE, value, notes)

    # 2) Hash formats -------------------------------------------------------
    if RE_SHA256.match(value):
        notes.append("Valid SHA-256 hash format (64 hexadecimal characters).")
        notes.append("Hashes are analysed as data only - never submitted to "
                     "online services and never used to fetch files.")
        return _result(True, TYPE_SHA256, value.lower(), notes)
    if RE_SHA1.match(value):
        notes.append("Valid SHA-1 hash format (40 hexadecimal characters).")
        return _result(True, TYPE_SHA1, value.lower(), notes)
    if RE_MD5.match(value):
        notes.append("Valid MD5 hash format (32 hexadecimal characters).")
        return _result(True, TYPE_MD5, value.lower(), notes)

    # 3) URL ---------------------------------------------------------------
    if value.lower().startswith(("http://", "https://", "ftp://")):
        return _validate_url(value)

    # 4) IPv4 / IPv6 -------------------------------------------------------
    try:
        ip = ipaddress.ip_address(value)
        if ip.version == 4:
            notes.append(f"Valid IPv4 address ({ip}).")
            notes.append("Address is treated as data only - it is never "
                         "contacted, pinged or scanned by this application.")
            return _result(True, TYPE_IPV4, str(ip), notes)
        notes.append(f"Valid IPv6 address ({ip}).")
        notes.append("Address is treated as data only - it is never contacted.")
        return _result(True, TYPE_IPV6, str(ip), notes)
    except ValueError:
        pass

    # 5) E-mail address -> validate the sender DOMAIN part ------------------
    if "@" in value and not value.startswith("@") and " " not in value:
        domain = value.rsplit("@", 1)[1]
        domain_result = _validate_domain(domain)
        if domain_result["valid"]:
            notes.append(f"Valid e-mail address; sender domain '{domain}' is valid.")
            notes.append("Only the sender domain is used for lookups; the full "
                         "address is not needed (data minimisation).")
            return _result(True, TYPE_EMAIL_DOMAIN, domain.lower(), notes)
        notes.append("E-mail address supplied but the sender domain is not valid.")
        return _result(False, TYPE_EMAIL_DOMAIN, domain.lower(), notes)

    # 6) Bare domain --------------------------------------------------------
    domain_result = _validate_domain(value)
    if domain_result["valid"]:
        return domain_result

    # 7) Anything else ------------------------------------------------------
    notes.append("Input does not match any supported indicator format "
                 "(IPv4, IPv6, domain, URL, MD5/SHA-1/SHA-256 hash, CVE ID).")
    notes.append("Validation checks SYNTAX only. A valid indicator is not "
                 "automatically malicious, and an invalid one is ignored safely.")
    return _result(False, TYPE_UNKNOWN, value, notes)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_domain(value: str) -> Dict:
    notes: List[str] = []
    value = value.strip().rstrip(".")
    if len(value) > 253:
        notes.append("Domain exceeds the 253-character maximum.")
        return _result(False, TYPE_DOMAIN, value, notes)
    if not RE_DOMAIN.match(value):
        notes.append("Not a syntactically valid domain name "
                     "(labels 1-63 chars, valid TLD required).")
        return _result(False, TYPE_DOMAIN, value.lower(), notes)
    if "*" in value:
        notes.append("Wildcard characters are not valid in a concrete indicator.")
        return _result(False, TYPE_DOMAIN, value.lower(), notes)
    notes.append(f"Valid domain format ({value.lower()}).")
    notes.append("Domain is analysed as data only - never resolved, visited "
                 "or contacted by this application.")
    return _result(True, TYPE_DOMAIN, value.lower(), notes)


def _validate_url(value: str) -> Dict:
    notes: List[str] = []
    try:
        parsed = urlparse(value)
    except ValueError:
        notes.append("URL could not be parsed.")
        return _result(False, TYPE_URL, value, notes)

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https", "ftp"):
        notes.append(f"Unsupported URL scheme '{scheme}'. Only http/https/ftp "
                     "are recognised.")
        return _result(False, TYPE_URL, value, notes)
    if not parsed.netloc:
        notes.append("URL has no host component.")
        return _result(False, TYPE_URL, value, notes)

    host = parsed.hostname or ""
    host_valid = _validate_domain(host)["valid"]
    try:
        ipaddress.ip_address(host)
        host_valid = True
    except ValueError:
        pass
    if not host_valid:
        notes.append(f"URL host '{host}' is not a valid domain or IP.")
        return _result(False, TYPE_URL, value, notes)

    notes.append(f"Valid URL (scheme={scheme}, host={host.lower()}).")
    notes.append("CRITICAL SAFETY NOTE: this application performs a local "
                 "database lookup only. It never visits, fetches or opens URLs.")
    return _result(True, TYPE_URL, value, notes)


def _result(valid: bool, indicator_type: str, normalized: str, notes) -> Dict:
    return {
        "valid": valid,
        "indicator_type": indicator_type,
        "normalized_value": normalized,
        "validation_notes": notes,
    }


def coarse_type(fine_type: str) -> str:
    """Map a fine-grained validated type to the coarse dataset category."""
    return {
        TYPE_IPV4: "IP ADDRESS",
        TYPE_IPV6: "IP ADDRESS",
        TYPE_DOMAIN: "DOMAIN",
        TYPE_EMAIL_DOMAIN: "EMAIL DOMAIN",
        TYPE_URL: "URL",
        TYPE_MD5: "FILE HASH",
        TYPE_SHA1: "FILE HASH",
        TYPE_SHA256: "FILE HASH",
        TYPE_CVE: "CVE ID",
    }.get(fine_type, "UNKNOWN")


# --- Detection helper (used by the search UI to accept anything) -----------

def looks_like_indicator(value: str) -> bool:
    """Quick check used by the UI to enable the search button."""
    return validate_indicator(value)["valid"]
