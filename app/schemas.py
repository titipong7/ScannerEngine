"""Request/response contracts shared by every scanner endpoint."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.dns_client import normalize_domain


class ScanStatus(str, Enum):
    """Coarse verdict stored in Supabase so the dashboard can colour a row."""

    PASS = "pass"        # configured and valid
    WARN = "warn"        # present but weak / incomplete
    FAIL = "fail"        # missing or broken
    ERROR = "error"      # we could not determine it (NXDOMAIN, timeout, ...)


class ScanType(str, Enum):
    DNSSEC = "dnssec"
    EMAIL = "email"
    TLS = "tls"


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253, examples=["cloudflare.com"])

    @field_validator("domain")
    @classmethod
    def _clean(cls, value: str) -> str:
        return normalize_domain(value)


class TLSScanRequest(ScanRequest):
    port: int = Field(443, ge=1, le=65535, description="TLS port to connect to")


class ComponentScore(BaseModel):
    key: str
    label: str
    status: ScanStatus
    weight: int
    credit: float | None = Field(None, description="1.0 pass, 0.5 warn, 0.0 fail, null undetermined")
    points: float


class ScoreBreakdown(BaseModel):
    score: int | None = Field(None, ge=0, le=100)
    grade: str | None = None
    coverage: float = Field(0.0, description="Share of the scoring model we could evaluate")
    earned_weight: float = 0.0
    available_weight: int = 0
    total_weight: int = 0
    components: list[ComponentScore] = Field(default_factory=list)
    undetermined: list[str] = Field(default_factory=list)
    note: str | None = None


class ScanResponse(BaseModel):
    domain: str
    scan_type: ScanType
    status: ScanStatus
    summary: str
    findings: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    scanned_at: datetime
    persisted: bool = False
    record_id: str | int | None = None


class FullScanResponse(BaseModel):
    """Every module plus the combined score, from one request."""

    domain: str
    scanned_at: datetime
    duration_ms: int
    score: ScoreBreakdown
    modules: list[ScanResponse]
    scan_id: str | int | None = None
    persisted: bool = False
