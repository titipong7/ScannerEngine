"""Supabase persistence for scan results.

The client is created lazily and shared. Persistence is deliberately
*best effort*: a Supabase outage degrades the engine to a read-only scanner
instead of failing the caller's request.

Expected table (see README for the full DDL):

    scan_results(id, domain, scan_type, status, summary, findings, raw_data, created_at)
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
    ) -> str | int | None:
        """Insert one row; returns the new row id, or None if it was not stored.

        Never raises — storage problems are logged and reported to the caller
        through the `persisted` flag on the response.
        """
        if self._client is None:
            return None

        payload = {
            "domain": domain,
            "scan_type": scan_type,
            "status": status,
            "summary": summary,
            "findings": findings,
            "raw_data": raw_data,
            "created_at": scanned_at.isoformat(),
        }
        try:
            response = self._client.table(self._table).insert(payload).execute()
        except Exception:  # network error, RLS denial, schema mismatch, ...
            logger.exception("Failed to store %s scan for %s in Supabase", scan_type, domain)
            return None

        rows = getattr(response, "data", None) or []
        return rows[0].get("id") if rows else None


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
