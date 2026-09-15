"""Supabase persistence for scan results.

The client is created lazily and shared. Persistence is deliberately
*best effort*: a Supabase outage degrades the engine to a read-only scanner
instead of failing the caller's request.

Tables it writes to (full DDL in `supabase/schema.sql`):

    scans(id, domain, user_id, trigger, score, grade, duration_ms, created_at)
    scan_results(id, scan_id, domain, scan_type, status, summary, findings, raw_data, ...)
    scores(id, scan_id, domain, score, grade, coverage, breakdown, created_at)
"""

from __future__ import annotations

import logging
from datetime import datetime
from functools import lru_cache
from typing import Any

from supabase import Client, create_client

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)


class SupabaseRepository:
    """Insert scan results into the `scan_results` table."""

    def __init__(self, client: Client | None, table: str) -> None:
        self._client = client
        self._table = table

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def _insert(self, table: str, payload: dict[str, Any], *, context: str) -> str | int | None:
        """Insert one row and return its id, or None if it could not be stored."""
        if self._client is None:
            return None
        try:
            response = self._client.table(table).insert(payload).execute()
        except Exception:  # network error, RLS denial, schema mismatch, ...
            logger.exception("Failed to store %s in Supabase", context)
            return None

        rows = getattr(response, "data", None) or []
        return rows[0].get("id") if rows else None

    def create_scan(
        self,
        *,
        domain: str,
        trigger: str = "manual",
        user_id: str | None = None,
    ) -> str | int | None:
        """Open a scan row that the per-module results will hang off."""
        payload: dict[str, Any] = {"domain": domain, "trigger": trigger}
        if user_id:
            payload["user_id"] = user_id
        return self._insert("scans", payload, context=f"scan for {domain}")

    def finish_scan(
        self,
        scan_id: str | int,
        *,
        score: int | None,
        grade: str | None,
        duration_ms: int,
    ) -> bool:
        """Write the final score back onto the scan row."""
        if self._client is None:
            return False
        try:
            self._client.table("scans").update(
                {"score": score, "grade": grade, "duration_ms": duration_ms}
            ).eq("id", scan_id).execute()
        except Exception:
            logger.exception("Failed to finalise scan %s in Supabase", scan_id)
            return False
        return True

    def insert_score(
        self,
        *,
        scan_id: str | int,
        domain: str,
        score: int,
        grade: str,
        coverage: float,
        breakdown: list[dict[str, Any]],
        user_id: str | None = None,
    ) -> str | int | None:
        payload: dict[str, Any] = {
            "scan_id": scan_id,
            "domain": domain,
            "score": score,
            "grade": grade,
            "coverage": coverage,
            "breakdown": breakdown,
        }
        if user_id:
            payload["user_id"] = user_id
        return self._insert("scores", payload, context=f"score for {domain}")

    def insert_scan_result(
        self,
        *,
        domain: str,
        scan_type: str,
        status: str,
        summary: str,
        findings: list[str],
        raw_data: dict[str, Any],
        scanned_at: datetime,
        scan_id: str | int | None = None,
        user_id: str | None = None,
    ) -> str | int | None:
        """Insert one row; returns the new row id, or None if it was not stored.

        Never raises — storage problems are logged and reported to the caller
        through the `persisted` flag on the response.
        """
        payload: dict[str, Any] = {
            "domain": domain,
            "scan_type": scan_type,
            "status": status,
            "summary": summary,
            "findings": findings,
            "raw_data": raw_data,
            "created_at": scanned_at.isoformat(),
        }
        if scan_id is not None:
            payload["scan_id"] = scan_id
        if user_id:
            payload["user_id"] = user_id
        return self._insert(self._table, payload, context=f"{scan_type} scan for {domain}")


def _build_client(settings: Settings) -> Client | None:
    if not settings.supabase_enabled:
        logger.warning(
            "Supabase is not configured (SUPABASE_URL / SUPABASE_KEY missing or "
            "PERSIST_RESULTS=false); scan results will not be stored."
        )
        return None
    try:
        return create_client(settings.supabase_url, settings.supabase_key)
    except Exception:
        logger.exception("Could not initialise the Supabase client; running without persistence")
        return None


@lru_cache
def get_repository() -> SupabaseRepository:
    settings = get_settings()
    return SupabaseRepository(_build_client(settings), settings.supabase_table)
