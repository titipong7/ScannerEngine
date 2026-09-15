"""SPF + DMARC scanner.

SPF  (RFC 7208): a single TXT record at the apex starting with `v=spf1`.
DMARC(RFC 7489): a TXT record at `_dmarc.<domain>` starting with `v=DMARC1`.

Beyond "does it exist", the scanner grades the records the way a mail receiver
would: a `+all` SPF record or a `p=none` DMARC policy is technically present but
offers no protection, so those come back as `warn`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import dns.resolver

from app.dns_client import DNSLookupError, txt_records
from app.schemas import ScanStatus

logger = logging.getLogger(__name__)

# Mechanisms that cost a DNS lookup; RFC 7208 §4.6.4 caps the total at 10.
_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}

_QUALIFIER_MEANING = {
    "+": ("pass", "accepts mail from any server — the record provides no protection"),
    "?": ("neutral", "is neutral, so unauthorised senders are not rejected"),
    "~": ("softfail", "soft-fails unauthorised senders (recommended while ramping up)"),
    "-": ("fail", "hard-fails unauthorised senders (strongest setting)"),
}

_VALID_POLICIES = {"none", "quarantine", "reject"}


def _parse_spf(record: str) -> dict[str, Any]:
    terms = record.split()[1:]  # drop the v=spf1 version term
    mechanisms = [t for t in terms if not re.match(r"^[a-z0-9_-]+=", t, re.IGNORECASE)]
    modifiers = dict(
        t.split("=", 1) for t in terms if re.match(r"^[a-z0-9_-]+=", t, re.IGNORECASE)
    )

    all_term = next((t for t in terms if t.lstrip("+-~?").lower() == "all"), None)
    qualifier = all_term[0] if all_term and all_term[0] in "+-~?" else ("+" if all_term else None)

    def mechanism_name(term: str) -> str:
        # "+include:_spf.example.com" -> "include", "a/24" -> "a"
        return re.split(r"[:/]", term.lstrip("+-~?"), maxsplit=1)[0].lower()

    lookups = sum(1 for t in mechanisms if mechanism_name(t) in _LOOKUP_MECHANISMS)
    lookups += sum(1 for k in modifiers if k.lower() in ("redirect", "exp"))

    return {
        "terms": terms,
        "mechanisms": mechanisms,
        "modifiers": modifiers,
        "all_qualifier": qualifier,
        "all_policy": _QUALIFIER_MEANING.get(qualifier or "", ("missing", ""))[0],
        "includes": [
            t.split(":", 1)[1] for t in mechanisms if mechanism_name(t) == "include" and ":" in t
        ],
        "dns_lookup_count": lookups,
    }


def _parse_dmarc(record: str) -> dict[str, Any]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()

    return {
        "tags": tags,
        "policy": tags.get("p", "").lower(),
        "subdomain_policy": tags.get("sp", "").lower() or None,
        "percentage": int(tags["pct"]) if tags.get("pct", "").isdigit() else 100,
        "aggregate_reports": [u.strip() for u in tags.get("rua", "").split(",") if u.strip()],
        "forensic_reports": [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()],
        "alignment_dkim": tags.get("adkim", "r").lower(),
        "alignment_spf": tags.get("aspf", "r").lower(),
    }


def _check_spf(domain: str, resolver: dns.resolver.Resolver, raw: dict[str, Any]) -> tuple[ScanStatus, list[str]]:
    findings: list[str] = []
    try:
        records = txt_records(resolver, domain)
    except DNSLookupError as exc:
        raw["spf"] = {"present": False, "error": exc.message, "reason": exc.reason}
        if exc.reason == "no_answer":
            findings.append("No TXT records at the apex, so no SPF record is published.")
            return ScanStatus.FAIL, findings
        findings.append(f"SPF lookup failed: {exc.message}")
        return ScanStatus.ERROR, findings

    spf_records = [r for r in records if r.lower().startswith("v=spf1")]
    raw["spf"] = {"present": bool(spf_records), "records": spf_records}

    if not spf_records:
        findings.append("No SPF record found — anyone can spoof mail from this domain.")
        return ScanStatus.FAIL, findings

    if len(spf_records) > 1:
        findings.append(
            f"{len(spf_records)} SPF records published; RFC 7208 allows exactly one, so receivers "
            "will treat the result as permerror."
        )
        raw["spf"]["parsed"] = _parse_spf(spf_records[0])
        return ScanStatus.FAIL, findings

    parsed = _parse_spf(spf_records[0])
    raw["spf"]["parsed"] = parsed

    status = ScanStatus.PASS
    qualifier = parsed["all_qualifier"]
    if qualifier is None:
        findings.append("SPF record has no 'all' mechanism — the default (neutral) offers no protection.")
        status = ScanStatus.WARN
    elif qualifier in ("+", "?"):
        _, explanation = _QUALIFIER_MEANING[qualifier]
        findings.append(f"SPF record uses '{qualifier}all' and {explanation}.")
        status = ScanStatus.WARN

    if parsed["dns_lookup_count"] > 10:
        findings.append(
            f"SPF record needs about {parsed['dns_lookup_count']} DNS lookups; the RFC limit is 10 "
            "and receivers will return permerror."
        )
        status = ScanStatus.FAIL

    return status, findings


def _check_dmarc(domain: str, resolver: dns.resolver.Resolver, raw: dict[str, Any]) -> tuple[ScanStatus, list[str]]:
    findings: list[str] = []
    qname = f"_dmarc.{domain}"
    try:
        records = txt_records(resolver, qname)
    except DNSLookupError as exc:
        raw["dmarc"] = {"present": False, "error": exc.message, "reason": exc.reason}
        if exc.reason in ("no_answer", "nxdomain"):
            findings.append(f"No DMARC record published at {qname}.")
            return ScanStatus.FAIL, findings
        findings.append(f"DMARC lookup failed: {exc.message}")
        return ScanStatus.ERROR, findings

    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]
    raw["dmarc"] = {"present": bool(dmarc_records), "records": dmarc_records, "queried": qname}

    if not dmarc_records:
        findings.append(f"No DMARC record published at {qname}.")
        return ScanStatus.FAIL, findings

    if len(dmarc_records) > 1:
        findings.append("Multiple DMARC records found; receivers will ignore all of them.")
        raw["dmarc"]["parsed"] = _parse_dmarc(dmarc_records[0])
        return ScanStatus.FAIL, findings

    parsed = _parse_dmarc(dmarc_records[0])
    raw["dmarc"]["parsed"] = parsed

    policy = parsed["policy"]
    if policy not in _VALID_POLICIES:
        findings.append(f"DMARC record has a missing or invalid policy tag (p={policy or 'unset'!r}).")
        return ScanStatus.FAIL, findings

    status = ScanStatus.PASS
    if policy == "none":
        findings.append("DMARC policy is 'p=none' — reports are collected but nothing is enforced.")
        status = ScanStatus.WARN
    elif policy == "quarantine":
        findings.append("DMARC policy is 'p=quarantine'; 'p=reject' is the strongest setting.")
        status = ScanStatus.WARN

    if parsed["percentage"] < 100:
        findings.append(f"DMARC only applies to {parsed['percentage']}% of mail (pct={parsed['percentage']}).")
        status = ScanStatus.WARN
    if not parsed["aggregate_reports"]:
        findings.append("No 'rua' address configured, so no aggregate reports will be received.")
        status = ScanStatus.WARN if status is ScanStatus.PASS else status
    if parsed["subdomain_policy"] == "none" and policy != "none":
        findings.append("Subdomain policy 'sp=none' weakens the parent policy for subdomains.")
        status = ScanStatus.WARN if status is ScanStatus.PASS else status

    return status, findings


def scan(domain: str, resolver: dns.resolver.Resolver) -> tuple[ScanStatus, str, list[str], dict[str, Any]]:
    """Return (status, summary, findings, raw_data) for SPF + DMARC."""
    raw: dict[str, Any] = {"domain": domain, "resolvers": list(resolver.nameservers)}

    spf_status, spf_findings = _check_spf(domain, resolver, raw)

    # A domain that does not exist has no email posture to grade. Reporting
    # "no DMARC record" here would score a typo as a misconfigured domain.
    if raw["spf"].get("reason") == "nxdomain":
        message = raw["spf"]["error"]
        raw["dmarc"] = {"present": False, "reason": "nxdomain", "error": message,
                        "status": ScanStatus.ERROR.value}
        raw["spf"]["status"] = ScanStatus.ERROR.value
        return ScanStatus.ERROR, message, [message], raw

    dmarc_status, dmarc_findings = _check_dmarc(domain, resolver, raw)

    raw["spf"]["status"] = spf_status.value
    raw["dmarc"]["status"] = dmarc_status.value

    findings = [f"SPF: {f}" for f in spf_findings] + [f"DMARC: {f}" for f in dmarc_findings]

    # Worst of the two wins.
    order = [ScanStatus.PASS, ScanStatus.WARN, ScanStatus.FAIL, ScanStatus.ERROR]
    status = max((spf_status, dmarc_status), key=order.index)

    summaries = {
        ScanStatus.PASS: "SPF and DMARC are both published and correctly configured.",
        ScanStatus.WARN: "SPF and DMARC are published but weakly configured.",
        ScanStatus.FAIL: "Email authentication is missing or broken for this domain.",
        ScanStatus.ERROR: "Email authentication could not be determined.",
    }
    return status, summaries[status], findings, raw
