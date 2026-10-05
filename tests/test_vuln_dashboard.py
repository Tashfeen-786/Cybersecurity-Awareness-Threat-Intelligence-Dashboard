"""
Vulnerability scoring, dashboard statistics, filtering and sorting tests
(scenarios 25-29 from the project brief).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from services.vulnerability_service import (  # noqa: E402
    calculate_vulnerability_priority, cvss_severity)


# T-025 - Vulnerability scoring / contextual prioritization
def test_T025_vulnerability_priority_contextual():
    # Teaching example A: CRITICAL CVSS on isolated lab asset -> lower priority
    lab = calculate_vulnerability_priority(
        cvss_score=9.8, asset_criticality=2, exposure="Isolated lab",
        exploitation_status="No known exploitation (synthetic)",
        business_context="Non-production / test", patch_available=True)
    # Teaching example B: HIGH CVSS, internet-facing critical, exploited
    vpn = calculate_vulnerability_priority(
        cvss_score=8.1, asset_criticality=5, exposure="Internet-facing",
        exploitation_status="Active exploitation observed (synthetic)",
        business_context="Mission-critical production", patch_available=True)
    assert lab["priority_score"] < vpn["priority_score"], \
        "context must be able to outrank raw CVSS"
    assert vpn["priority_band"] == "CRITICAL"
    assert len(lab["breakdown"]) == 5  # five contextual factors
    assert lab["priority_score"] == 52
    assert vpn["priority_score"] == 93


def test_T025b_cvss_severity_bands():
    assert cvss_severity(9.8) == "CRITICAL"
    assert cvss_severity(7.5) == "HIGH"
    assert cvss_severity(5.0) == "MEDIUM"
    assert cvss_severity(2.1) == "LOW"


def test_T025c_vulnerability_api(client):
    data = client.get("/api/vulnerabilities").json()
    assert data["total"] == 60
    assert data["items"][0]["priority_score"] >= data["items"][-1]["priority_score"]
    detail = client.get("/api/vulnerabilities/CVE-2026-900002").json()
    assert detail["priority_score"] == 93
    assert len(detail["priority_breakdown"]) == 5
    assert detail["recommended_actions"]
    assert client.get("/api/vulnerabilities/CVE-9999-000001").status_code == 404


# T-026 - Dashboard statistics
def test_T026_dashboard_statistics(client):
    data = client.get("/api/dashboard/stats").json()
    cards = data["cards"]
    assert cards["total_threat_records"] == 2200
    assert cards["critical_threats"] > 0
    assert cards["high_threats"] > 0
    assert cards["active_indicators"] > 1000
    assert cards["open_investigations"] > 0
    assert 0 <= cards["average_confidence"] <= 100
    assert cards["vulnerabilities_tracked"] == 60
    # all ten chart datasets are present
    charts = data["charts"]
    for key in ["threats_by_severity", "threats_by_category",
                "ioc_type_distribution", "top_attack_tactics",
                "vulnerabilities_by_severity", "top_threat_categories",
                "threat_status_distribution"]:
        assert charts[key], key
    trends = client.get("/api/dashboard/trends").json()
    assert len(trends["threats_over_time"]) >= 12   # monthly series
    assert len(trends["risk_distribution"]) == 5    # five risk bands
    assert len(trends["confidence_distribution"]) == 5


# T-027 - Severity filtering
def test_T027_severity_filtering(client):
    data = client.get("/api/threats?severity=CRITICAL&page_size=50").json()
    assert data["total"] > 0
    assert all(t["severity"] == "CRITICAL" for t in data["items"])
    # invalid severity -> 400
    assert client.get("/api/threats?severity=WOBBLE").status_code == 400


# T-028 - Category filtering
def test_T028_category_filtering(client):
    data = client.get("/api/threats?category=Phishing&page_size=50").json()
    assert data["total"] > 100
    assert all(t["threat_category"] == "Phishing" for t in data["items"])


# T-029 - Threat sorting
def test_T029_threat_sorting(client):
    by_risk = client.get("/api/threats?sort=risk&page_size=100").json()["items"]
    risks = [t["risk_score"] for t in by_risk]
    assert risks == sorted(risks, reverse=True)

    by_conf = client.get("/api/threats?sort=confidence&page_size=100").json()["items"]
    confs = [t["confidence_score"] for t in by_conf]
    assert confs == sorted(confs, reverse=True)

    by_obs = client.get("/api/threats?sort=observed&page_size=100").json()["items"]
    obs = [t["observation_count"] for t in by_obs]
    assert obs == sorted(obs, reverse=True)

    by_new = client.get("/api/threats?sort=newest&page_size=100").json()["items"]
    dates = [t["last_seen"] for t in by_new]
    assert dates == sorted(dates, reverse=True)
