"""Pydantic request/response schemas for API validation."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class ThreatCreate(BaseModel):
    """POST /api/threats request body."""
    threat_name: str = Field(..., min_length=3, max_length=200,
                             description="Short name for the threat record")
    threat_category: str = Field(..., description="One of the 10 threat categories")
    indicator_type: str = Field(..., description="IP ADDRESS | DOMAIN | URL | "
                                                 "FILE HASH | EMAIL DOMAIN | CVE ID")
    indicator_value: str = Field(..., min_length=3, max_length=2048,
                                 description="The indicator (validated server-side)")
    severity: str = Field(..., description="INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL")
    confidence_score: int = Field(50, ge=0, le=100)
    description: Optional[str] = Field("", max_length=2000)
    source_name: Optional[str] = Field("Internal SOC", max_length=100)

    @field_validator("threat_category")
    @classmethod
    def valid_category(cls, v):
        allowed = {"Phishing", "Malware", "Ransomware", "Credential Theft",
                   "Web Threats", "Network Threats", "Vulnerability Exposure",
                   "Social Engineering", "Data Exposure", "Account Security"}
        if v not in allowed:
            raise ValueError(f"threat_category must be one of {sorted(allowed)}")
        return v

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, v):
        allowed = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return v.upper()


class ThreatUpdate(BaseModel):
    """PUT /api/threats/{id} request body."""
    status: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    threat_name: Optional[str] = None
    country_or_region: Optional[str] = None

    @field_validator("status")
    @classmethod
    def valid_status(cls, v):
        if v is None:
            return v
        allowed = {"NEW", "UNDER_REVIEW", "MONITORING", "CLOSED",
                   "FALSE_POSITIVE"}
        if v.upper() not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return v.upper()


class NoteCreate(BaseModel):
    """POST /api/threats/{id}/notes request body."""
    note: str = Field(..., min_length=3, max_length=2000)
    anonymous_author: Optional[str] = Field(None, max_length=60)


class AlertStatusUpdate(BaseModel):
    """PUT /api/alerts/{id}/status request body."""
    status: str

    @field_validator("status")
    @classmethod
    def valid_status(cls, v):
        allowed = {"NEW", "INVESTIGATING", "MONITORING", "RESOLVED",
                   "FALSE_POSITIVE"}
        if v.upper() not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return v.upper()


class QuizAnswer(BaseModel):
    question_id: str
    selected_option: int = Field(..., ge=0, le=3)


class QuizSubmit(BaseModel):
    """POST /api/quiz/submit request body."""
    answers: List[QuizAnswer] = Field(..., min_length=1)
    anonymous_user_id: Optional[str] = Field(
        None, max_length=60,
        description="Optional anonymous label. No personal data is collected.")
