"""Scanner Engine — DNSSEC and email-authentication scanning API.

Run locally:      uvicorn main:app --reload
Run in Docker:    docker compose up --build
Interactive docs: http://localhost:8000/docs
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from functools import partial
from datetime import datetime, timezone
from typing import Annotated, Any, Callable

import dns.resolver
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from app.config import Settings, get_settings
from app.dns_client import build_resolver
from app import scoring
from app.schemas import (
    FullScanResponse,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanType,
    ScoreBreakdown,
    TLSScanRequest,
)
from app.scanners import dnssec as dnssec_scanner
from app.scanners import email_auth as email_scanner
from app.scanners import tls as tls_scanner
from app.storage import SupabaseRepository, get_repository

logger = logging.getLogger("scanner_engine")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    repository = get_repository()
    logger.info(
        "Scanner Engine starting — resolvers=%s, supabase=%s",
        settings.resolver_list,
        "enabled" if repository.enabled else "disabled",
    )
    yield
    logger.info("Scanner Engine shutting down")


app = FastAPI(
    title="Scanner Engine",
    description="DNSSEC and email authentication (SPF/DMARC) scanning for the Web Audit Platform.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # tighten to the dashboard origin in production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #
SettingsDep = Annotated[Settings, Depends(get_settings)]
RepositoryDep = Annotated[SupabaseRepository, Depends(get_repository)]


async def require_api_key(
    settings: SettingsDep,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    """No-op unless API_KEY is set, so local development stays frictionless."""
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing X-API-Key header")


# --------------------------------------------------------------------------- #
# Shared scan pipeline
# --------------------------------------------------------------------------- #
ScanFn = Callable[[str, dns.resolver.Resolver], tuple[ScanStatus, str, list[str], dict[str, Any]]]


async def execute_scan(
    *,
    domain: str,
    scan_type: ScanType,
    scan_fn: ScanFn,
    settings: Settings,
    want_dnssec: bool = False,
) -> ScanResponse:
    """Run one scanner off the event loop. Does not touch the database."""
    resolver = build_resolver(
        settings.resolver_list,
        settings.dns_timeout,
        settings.dns_lifetime,
        want_dnssec=want_dnssec,
    )

    try:
        status_, summary, findings, raw_data = await run_in_threadpool(scan_fn, domain, resolver)
    except Exception:
        logger.exception("Unhandled error during %s scan of %s", scan_type.value, domain)
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"The {scan_type.value} scan of '{domain}' failed unexpectedly.",
        ) from None

    return ScanResponse(
        domain=domain,
        scan_type=scan_type,
        status=status_,
        summary=summary,
        findings=findings,
        raw_data=raw_data,
        scanned_at=datetime.now(timezone.utc),
    )


async def persist(
    result: ScanResponse,
    repository: SupabaseRepository,
    *,
    scan_id: str | int | None = None,
) -> ScanResponse:
    """Store one module's result, folding the row id back into the response."""
    record_id = await run_in_threadpool(
        repository.insert_scan_result,
        domain=result.domain,
        scan_type=result.scan_type.value,
        status=result.status.value,
        summary=result.summary,
        findings=result.findings,
        raw_data=result.raw_data,
        scanned_at=result.scanned_at,
        scan_id=scan_id,
    )
    return result.model_copy(update={"persisted": record_id is not None, "record_id": record_id})


async def run_scan(
    *,
    domain: str,
    scan_type: ScanType,
    scan_fn: ScanFn,
    settings: Settings,
    repository: SupabaseRepository,
    want_dnssec: bool = False,
) -> ScanResponse:
    """Execute a scanner, then persist the result."""
    result = await execute_scan(
        domain=domain,
        scan_type=scan_type,
        scan_fn=scan_fn,
        settings=settings,
        want_dnssec=want_dnssec,
    )
    return await persist(result, repository)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/health", tags=["system"], summary="Liveness / readiness probe")
async def health(settings: SettingsDep, repository: RepositoryDep) -> dict[str, Any]:
    return {
        "status": "ok",
        "version": app.version,
        "supabase": "connected" if repository.enabled else "disabled",
        "resolvers": settings.resolver_list,
    }


@app.post(
    "/scan/dns",
    response_model=ScanResponse,
    tags=["scan"],
    summary="Check the DNSSEC posture of a domain",
    dependencies=[Depends(require_api_key)],
)
async def scan_dns(payload: ScanRequest, settings: SettingsDep, repository: RepositoryDep) -> ScanResponse:
    """Validate that DS, DNSKEY and RRSIG records exist and form a valid chain of trust.

    Also warns when a signature is close to expiring, since an expired RRSIG takes
    the entire domain offline for validating resolvers.
    """
    return await run_scan(
        domain=payload.domain,
        scan_type=ScanType.DNSSEC,
        scan_fn=partial(dnssec_scanner.scan, warn_days=settings.dnssec_expiry_warning_days),
        settings=settings,
        repository=repository,
        want_dnssec=True,
    )


@app.post(
    "/scan/email",
    response_model=ScanResponse,
    tags=["scan"],
    summary="Check SPF and DMARC records for a domain",
    dependencies=[Depends(require_api_key)],
)
async def scan_email(payload: ScanRequest, settings: SettingsDep, repository: RepositoryDep) -> ScanResponse:
    """Query and grade the domain's SPF record and its `_dmarc` policy record."""
    return await run_scan(
        domain=payload.domain,
        scan_type=ScanType.EMAIL,
        scan_fn=email_scanner.scan,
        settings=settings,
        repository=repository,
    )


@app.post(
    "/scan/tls",
    response_model=ScanResponse,
    tags=["scan"],
    summary="Check the SSL/TLS configuration of a domain",
    dependencies=[Depends(require_api_key)],
)
async def scan_tls(payload: TLSScanRequest, settings: SettingsDep, repository: RepositoryDep) -> ScanResponse:
    """Validate the certificate chain, expiry, protocol versions and HSTS."""
    return await run_scan(
        domain=payload.domain,
        scan_type=ScanType.TLS,
        scan_fn=partial(
            tls_scanner.scan,
            port=payload.port,
            timeout=settings.tls_timeout,
            warn_days=settings.tls_expiry_warning_days,
        ),
        settings=settings,
        repository=repository,
    )


@app.post(
    "/scan/full",
    response_model=FullScanResponse,
    tags=["scan"],
    summary="Run every module and return a single graded score",
    dependencies=[Depends(require_api_key)],
)
async def scan_full(payload: ScanRequest, settings: SettingsDep, repository: RepositoryDep) -> FullScanResponse:
    """Run DNSSEC, email and TLS together, score the result and store it.

    The three modules are independent network work, so they run concurrently —
    the whole scan costs about as long as its slowest module rather than the sum.
    """
    started = time.perf_counter()

    results = await asyncio.gather(
        execute_scan(
            domain=payload.domain,
            scan_type=ScanType.DNSSEC,
            scan_fn=partial(dnssec_scanner.scan, warn_days=settings.dnssec_expiry_warning_days),
            settings=settings,
            want_dnssec=True,
        ),
        execute_scan(
            domain=payload.domain,
            scan_type=ScanType.EMAIL,
            scan_fn=email_scanner.scan,
            settings=settings,
        ),
        execute_scan(
            domain=payload.domain,
            scan_type=ScanType.TLS,
            scan_fn=partial(
                tls_scanner.scan,
                timeout=settings.tls_timeout,
                warn_days=settings.tls_expiry_warning_days,
            ),
            settings=settings,
        ),
    )

    breakdown = scoring.score(
        {r.scan_type.value: {"status": r.status, "raw_data": r.raw_data} for r in results}
    )
    duration_ms = int((time.perf_counter() - started) * 1000)

    # One scan row ties the module results and the score together.
    scan_id = await run_in_threadpool(repository.create_scan, domain=payload.domain)
    modules = [await persist(result, repository, scan_id=scan_id) for result in results]

    if scan_id is not None:
        await run_in_threadpool(
            repository.finish_scan,
            scan_id,
            score=breakdown["score"],
            grade=breakdown["grade"],
            duration_ms=duration_ms,
        )
        if breakdown["score"] is not None:
            await run_in_threadpool(
                repository.insert_score,
                scan_id=scan_id,
                domain=payload.domain,
                score=breakdown["score"],
                grade=breakdown["grade"],
                coverage=breakdown["coverage"],
                breakdown=breakdown["components"],
            )

    return FullScanResponse(
        domain=payload.domain,
        scanned_at=min(r.scanned_at for r in modules),
        duration_ms=duration_ms,
        score=ScoreBreakdown(**breakdown),
        modules=modules,
        scan_id=scan_id,
        persisted=scan_id is not None,
    )


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
