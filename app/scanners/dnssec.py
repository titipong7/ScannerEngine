"""DNSSEC scanner.

The check answers three questions, in order:

1. Is the zone *signed*?            -> DNSKEY records exist at the apex.
2. Is the chain of trust *linked*?  -> a DS record in the parent zone whose
                                       digest matches one of the apex keys.
3. Are the signatures *valid*?      -> the RRSIG covering the DNSKEY RRset
                                       verifies against those keys, and a
                                       validating resolver sets the AD flag.

A zone that is signed but whose DS digest matches nothing (or whose signatures
have expired) is *worse* than an unsigned zone, so it is reported as `fail`
with an explicit finding rather than being lumped in with "not enabled".
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

from app.dns_client import DNSLookupError, resolve
from app.schemas import ScanStatus

logger = logging.getLogger(__name__)

# KSKs (the keys a DS can point at) carry the Secure Entry Point flag.
_SEP_FLAG = 0x0001


def _serialize_ds(rdata: Any) -> dict[str, Any]:
    return {
        "key_tag": rdata.key_tag,
        "algorithm": int(rdata.algorithm),
        "algorithm_name": dns.dnssec.algorithm_to_text(rdata.algorithm),
        "digest_type": int(rdata.digest_type),
        "digest": rdata.digest.hex(),
    }


def _serialize_dnskey(rdata: Any) -> dict[str, Any]:
    return {
        "key_tag": dns.dnssec.key_id(rdata),
        "flags": int(rdata.flags),
        "role": "KSK" if rdata.flags & _SEP_FLAG else "ZSK",
        "algorithm": int(rdata.algorithm),
        "algorithm_name": dns.dnssec.algorithm_to_text(rdata.algorithm),
    }


def _serialize_rrsig(rdata: Any) -> dict[str, Any]:
    to_utc = dt.datetime.fromtimestamp
    return {
        "type_covered": dns.rdatatype.to_text(rdata.type_covered),
        "key_tag": rdata.key_tag,
        "signer": str(rdata.signer).rstrip("."),
        "algorithm": int(rdata.algorithm),
        "algorithm_name": dns.dnssec.algorithm_to_text(rdata.algorithm),
        "inception": to_utc(rdata.inception, dt.timezone.utc).isoformat(),
        "expiration": to_utc(rdata.expiration, dt.timezone.utc).isoformat(),
        "expired": rdata.expiration < dt.datetime.now(dt.timezone.utc).timestamp(),
    }


def _find_rrsets(response: dns.message.Message, name: dns.name.Name) -> tuple[Any | None, Any | None]:
    """Pull the DNSKEY RRset and its covering RRSIG out of an answer section."""
    dnskey_rrset = rrsig_rrset = None
    for rrset in response.answer:
        if rrset.name != name:
            continue
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            dnskey_rrset = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG and rrset.covers == dns.rdatatype.DNSKEY:
            rrsig_rrset = rrset
    return dnskey_rrset, rrsig_rrset


def scan(domain: str, resolver: dns.resolver.Resolver) -> tuple[ScanStatus, str, list[str], dict[str, Any]]:
    """Return (status, summary, findings, raw_data) for the DNSSEC posture."""
    name = dns.name.from_text(domain)
    findings: list[str] = []
    raw: dict[str, Any] = {
        "domain": domain,
        "resolvers": list(resolver.nameservers),
        "ds_records": [],
        "dnskey_records": [],
        "rrsig_records": [],
        "checks": {
            "ds_present": False,
            "dnskey_present": False,
            "rrsig_present": False,
            "rrsig_valid": False,
            "ds_matches_dnskey": False,
            "ad_flag": False,
        },
        "errors": [],
    }
    checks = raw["checks"]

    # 1. DS record in the parent zone -----------------------------------------
    ds_rdatas: list[Any] = []
    try:
        ds_answer = resolve(resolver, domain, "DS")
        ds_rdatas = list(ds_answer)
        raw["ds_records"] = [_serialize_ds(r) for r in ds_rdatas]
        checks["ds_present"] = True
    except DNSLookupError as exc:
        raw["errors"].append({"step": "DS", "reason": exc.reason, "message": exc.message})
        if exc.fatal:
            return ScanStatus.ERROR, exc.message, [exc.message], raw
        findings.append("No DS record published in the parent zone — the chain of trust is not delegated.")

    # 2. DNSKEY + RRSIG at the apex -------------------------------------------
    dnskey_rrset = rrsig_rrset = None
    try:
        key_answer = resolve(resolver, domain, "DNSKEY")
        dnskey_rrset, rrsig_rrset = _find_rrsets(key_answer.response, name)
        checks["ad_flag"] = bool(key_answer.response.flags & dns.flags.AD)
    except DNSLookupError as exc:
        raw["errors"].append({"step": "DNSKEY", "reason": exc.reason, "message": exc.message})
        if exc.reason == "no_nameservers":
            findings.append(
                "The resolver refused to answer the DNSKEY query — this usually means DNSSEC "
                "validation is failing for this zone (SERVFAIL)."
            )
            return ScanStatus.FAIL, "DNSSEC appears to be misconfigured (validation failure).", findings, raw
        if exc.fatal:
            return ScanStatus.ERROR, exc.message, [exc.message], raw

    if dnskey_rrset is not None:
        checks["dnskey_present"] = True
        raw["dnskey_records"] = [_serialize_dnskey(r) for r in dnskey_rrset]
    if rrsig_rrset is not None:
        checks["rrsig_present"] = True
        raw["rrsig_records"] = [_serialize_rrsig(r) for r in rrsig_rrset]

    # Unsigned zone: nothing else to check.
    if not checks["dnskey_present"]:
        summary = "DNSSEC is not enabled — the zone publishes no DNSKEY records."
        findings.append(summary)
        return ScanStatus.FAIL, summary, findings, raw

    if not checks["rrsig_present"]:
        findings.append("DNSKEY records exist but no RRSIG covers them — the zone is not actually signed.")

    # 3. Cryptographically verify the DNSKEY RRset ----------------------------
    if dnskey_rrset is not None and rrsig_rrset is not None:
        try:
            dns.dnssec.validate(dnskey_rrset, rrsig_rrset, {name: dnskey_rrset})
            checks["rrsig_valid"] = True
        except dns.dnssec.ValidationFailure as exc:
            findings.append(f"RRSIG validation failed for the DNSKEY RRset: {exc}")
            raw["errors"].append({"step": "RRSIG", "reason": "validation_failure", "message": str(exc)})
        except Exception as exc:  # unsupported algorithm, missing crypto backend, ...
            findings.append(f"Could not verify the DNSKEY signature: {exc}")
            raw["errors"].append({"step": "RRSIG", "reason": "validation_error", "message": str(exc)})

        expired = [r for r in raw["rrsig_records"] if r["expired"]]
        if expired:
            findings.append(
                f"{len(expired)} RRSIG record(s) covering DNSKEY have expired — resolvers will SERVFAIL."
            )

    # 4. Does a DS digest actually match one of the published keys? -----------
    if ds_rdatas and dnskey_rrset is not None:
        matched: list[int] = []
        for ds in ds_rdatas:
            for key in dnskey_rrset:
                if dns.dnssec.key_id(key) != ds.key_tag:
                    continue
                try:
                    candidate = dns.dnssec.make_ds(name, key, ds.digest_type)
                except Exception as exc:  # unsupported digest type
                    raw["errors"].append({"step": "DS", "reason": "digest_error", "message": str(exc)})
                    continue
                if candidate == ds:
                    matched.append(ds.key_tag)
                    break
        raw["checks"]["matched_key_tags"] = sorted(set(matched))
        checks["ds_matches_dnskey"] = bool(matched)
        if not matched:
            findings.append(
                "No DS record matches a published DNSKEY — the chain of trust is broken "
                "(check for a stale DS at the registrar after a key rollover)."
            )

    if not checks["ad_flag"]:
        findings.append(
            "The validating resolver did not set the AD flag, so the answer could not be "
            "authenticated end to end."
        )

    # Verdict ------------------------------------------------------------------
    fully_valid = all(
        (checks["ds_present"], checks["dnskey_present"], checks["rrsig_present"],
         checks["rrsig_valid"], checks["ds_matches_dnskey"], checks["ad_flag"])
    )
    if fully_valid:
        return ScanStatus.PASS, "DNSSEC is enabled and the chain of trust validates.", findings, raw

    if checks["ds_present"] or checks["rrsig_present"]:
        return (
            ScanStatus.FAIL,
            "DNSSEC is partially configured but does not validate correctly.",
            findings,
            raw,
        )

    return ScanStatus.FAIL, "DNSSEC is not enabled for this domain.", findings, raw
