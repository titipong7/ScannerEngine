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
