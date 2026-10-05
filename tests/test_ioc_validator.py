"""
IOC Validation Engine tests (scenarios 1-11 from the project brief).

Validation means "is this SYNTACTICALLY VALID?" - never "is this malicious?"
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from services.ioc_validator import validate_indicator  # noqa: E402


# T-001 - Valid IPv4
def test_T001_valid_ipv4():
    result = validate_indicator("198.51.100.25")
    assert result["valid"] is True
    assert result["indicator_type"] == "ipv4"
    assert result["normalized_value"] == "198.51.100.25"
    assert any("never contacted" in n.lower() or "treated as data" in n.lower()
               for n in result["validation_notes"])


# T-002 - Invalid IPv4
def test_T002_invalid_ipv4():
    result = validate_indicator("192.0.2.999")           # octet > 255
    assert result["valid"] is False
    assert result["indicator_type"] == "unknown"
    for bad_ip in ["999.999.999.999", "192.0.2", "192.0.2.1.2"]:
        assert validate_indicator(bad_ip)["valid"] is False, bad_ip


# T-003 - Valid IPv6
def test_T003_valid_ipv6():
    result = validate_indicator("2001:db8::1")
    assert result["valid"] is True
    assert result["indicator_type"] == "ipv6"
    assert result["normalized_value"] == "2001:db8::1"


# T-004 - Valid domain
def test_T004_valid_domain():
    for domain in ["login-check.invalid", "example.com", "portal.example.org"]:
        result = validate_indicator(domain)
        assert result["valid"] is True, domain
        assert result["indicator_type"] == "domain"
        assert result["normalized_value"] == domain


# T-005 - Invalid domain
def test_T005_invalid_domain():
    for bad in ["-bad-.com", "not a domain", "under_score.invalid",
                "toolong" * 40 + ".com", "*.example.com"]:
        result = validate_indicator(bad)
        assert result["valid"] is False, bad


# T-006 - Valid URL
def test_T006_valid_url():
    result = validate_indicator("https://login-check.invalid/verify-account.html")
    assert result["valid"] is True
    assert result["indicator_type"] == "url"
    assert any("never visits" in n.lower() for n in result["validation_notes"])


# T-007 - Valid MD5-format hash
def test_T007_valid_md5():
    result = validate_indicator("d41d8cd98f00b204e9800998ecf8427e")
    assert result["valid"] is True
    assert result["indicator_type"] == "md5"
    assert result["normalized_value"] == "D41D8CD98F00B204E9800998ECF8427E".lower()


# T-008 - Valid SHA-1-format hash
def test_T008_valid_sha1():
    result = validate_indicator("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert result["valid"] is True
    assert result["indicator_type"] == "sha1"


# T-009 - Valid SHA-256-format hash
def test_T009_valid_sha256():
    result = validate_indicator(
        "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        "a1b2c3d4e5f60718293a4b5c6d7e8f90")
    assert result["valid"] is True
    assert result["indicator_type"] == "sha256"


# T-010 - Valid CVE format
def test_T010_valid_cve():
    result = validate_indicator("cve-2026-900001")
    assert result["valid"] is True
    assert result["indicator_type"] == "cve"
    assert result["normalized_value"] == "CVE-2026-900001"   # normalized uppercase


# T-011 - Invalid CVE format
def test_T011_invalid_cve():
    for bad in ["CVE-26-1", "CVE-2026-abc", "2026-900001", "CVE-2026-900001-x"]:
        result = validate_indicator(bad)
        assert result["valid"] is False, bad


# Extras: edge cases that keep the validator honest
def test_empty_and_oversized_inputs():
    assert validate_indicator("")["valid"] is False
    assert validate_indicator(None)["valid"] is False
    assert validate_indicator("x" * 3000)["valid"] is False


def test_email_sender_domain():
    result = validate_indicator("support@example.com")
    assert result["valid"] is True
    assert result["indicator_type"] == "email_domain"
    assert result["normalized_value"] == "example.com"
