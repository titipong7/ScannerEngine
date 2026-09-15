"""DKIM scanner.

DKIM is the awkward one, and the reason it was left until last: **a domain's
selectors cannot be enumerated over DNS.** A key lives at
`<selector>._domainkey.<domain>`, and nothing in DNS lists which selectors
exist. So a scanner can only do one of two things:

* the caller names the selectors — then "no record there" is a real failure;
* the scanner guesses from the selectors common providers use — and then *not
  finding one proves nothing at all*.

That distinction is carried all the way into the verdict. A failed guess is
reported as `error` (undeterminable), never `fail`, so the scoring model drops
it from the denominator instead of punishing a domain for a key we simply could
not locate. Claiming "no DKIM" from a failed guess would be the single most
misleading thing this whole engine could say.
"""

from __future__ import annotations

import base64
import binascii
import copy
import logging
import secrets
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import dns.resolver
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from app.dns_client import DNSLookupError, txt_records
from app.schemas import ScanStatus

logger = logging.getLogger(__name__)

# Selectors that the major providers publish at fixed, guessable names. Ordered
# roughly by how much mail they carry, since the first hit ends the search.
COMMON_SELECTORS: tuple[str, ...] = (
    "google",                       # Google Workspace
    "selector1", "selector2",       # Microsoft 365
    "k1", "k2",                     # Mailchimp / Mandrill
    "s1", "s2",                     # SendGrid, others
    "dkim", "default", "mail",      # self-hosted conventions
    "pm", "pm1",                    # Postmark
    "fm1", "fm2", "fm3",            # Fastmail
    "zoho", "zohomail",             # Zoho
    "protonmail", "protonmail2",    # Proton
    "mx", "smtp", "sig1",           # misc / Yahoo
)

# How many selector probes to run at once. DNS queries are almost all waiting,
# so this keeps a 20-selector sweep at roughly one query's wall time.
_PROBE_WORKERS = 8

# Guessing runs ~22 lookups, most of which are expected to miss. A full-length
# timeout on each would let one slow negative answer dominate a whole /scan/full,
# so probes get a shorter budget than a query whose answer we actually need.
_PROBE_LIFETIME_SECONDS = 4.0

# A domain can publish a wildcard record at *._domainkey, which makes *every*
# selector resolve. Probing one selector that cannot plausibly exist tells us
# whether the hits below are real keys or just the wildcard answering.
_SENTINEL_PREFIX = "scanner-probe"

# Below this an RSA key is trivially factorable by a well-resourced attacker.
_MIN_RSA_BITS = 1024
_RECOMMENDED_RSA_BITS = 2048


def _parse_dkim_record(record: str) -> dict[str, Any]:
    """Split a DKIM TXT record into its tag/value pairs."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def _inspect_public_key(encoded: str) -> dict[str, Any]:
    """Decode the `p=` tag and describe the key it holds."""
    cleaned = "".join(encoded.split())
    if not cleaned:
        # An empty p= is how a key is revoked (RFC 6376 s3.6.1).
        return {"present": False, "revoked": True}

    try:
        der = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        return {"present": True, "valid": False, "error": f"p= is not valid base64: {exc}"}

    try:
        key = load_der_public_key(der)
    except Exception as exc:
        return {"present": True, "valid": False, "error": f"p= is not a usable public key: {exc}"}

    if isinstance(key, rsa.RSAPublicKey):
        return {"present": True, "valid": True, "revoked": False, "type": "RSA", "bits": key.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"present": True, "valid": True, "revoked": False, "type": "Ed25519", "bits": 256}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"present": True, "valid": True, "revoked": False, "type": "EC", "bits": key.curve.key_size}
    return {"present": True, "valid": True, "revoked": False, "type": "unknown", "bits": None}


def _probe_selector(
    domain: str, selector: str, resolver: dns.resolver.Resolver
) -> dict[str, Any] | None:
    """Look up one selector. Returns None when nothing is published there."""
    qname = f"{selector}._domainkey.{domain}"
    try:
        records = txt_records(resolver, qname)
    except DNSLookupError as exc:
        if exc.reason in ("nxdomain", "no_answer"):
            return None
        # A timeout here is not "no key" — keep it so the caller can say so.
        return {"selector": selector, "qname": qname, "error": exc.message, "reason": exc.reason}

    # A DKIM record may omit v=DKIM1, but must carry a p= tag.
    candidates = [r for r in records if "p=" in r.lower() or r.lower().startswith("v=dkim1")]
    if not candidates:
        return None

    record = candidates[0]
    tags = _parse_dkim_record(record)
    return {
        "selector": selector,
        "qname": qname,
        "record": record,
        "tags": tags,
        "version": tags.get("v", "").upper() or None,
        "key_type": tags.get("k", "rsa").lower(),
        "testing": "y" in tags.get("t", "").lower().split(":"),
        "strict_subdomains": "s" in tags.get("t", "").lower().split(":"),
        "service_type": tags.get("s"),
        "public_key": _inspect_public_key(tags.get("p", "")),
    }


def _bounded(resolver: dns.resolver.Resolver) -> dns.resolver.Resolver:
    """A copy of the resolver with a shorter budget, for probes that may miss."""
    probe = copy.copy(resolver)
    probe.lifetime = min(getattr(resolver, "lifetime", _PROBE_LIFETIME_SECONDS) or
                         _PROBE_LIFETIME_SECONDS, _PROBE_LIFETIME_SECONDS)
    probe.timeout = min(getattr(resolver, "timeout", probe.lifetime) or probe.lifetime, probe.lifetime)
    return probe


def scan(
    domain: str,
    resolver: dns.resolver.Resolver,
    *,
    selectors: list[str] | None = None,
) -> tuple[ScanStatus, str, list[str], dict[str, Any]]:
    """Return (status, summary, findings, raw_data) for DKIM.

    Pass `selectors` when you know them — that is the only way a missing key can
    be reported as a failure rather than as "we could not find one".
    """
    explicit = bool(selectors)
    probe_list = list(selectors) if selectors else list(COMMON_SELECTORS)

    findings: list[str] = []
    raw: dict[str, Any] = {
        "domain": domain,
        "selectors_checked": probe_list,
        "selectors_were_supplied": explicit,
        "keys": [],
        "errors": [],
        "checks": {
            "key_found": False,
            "key_usable": False,
            "strong_key": False,
            "in_testing_mode": False,
        },
    }
    checks = raw["checks"]

    probe_resolver = _bounded(resolver)
    sentinel = f"{_SENTINEL_PREFIX}-{secrets.token_hex(6)}"
    with ThreadPoolExecutor(max_workers=_PROBE_WORKERS) as pool:
        results = list(
            pool.map(
                lambda s: _probe_selector(domain, s, probe_resolver), [sentinel, *probe_list]
            )
        )

    sentinel_hit, results = results[0], results[1:]
    wildcard = sentinel_hit is not None and "error" not in sentinel_hit
    raw["wildcard_record"] = wildcard

    for result in results:
        if result is None:
            continue
        if "error" in result:
            raw["errors"].append(result)
        else:
            raw["keys"].append(result)

    # Under a wildcard every "hit" is the same record, so report it once as what
    # it is rather than as 22 separate discoveries.
    if wildcard:
        raw["keys"] = [{**sentinel_hit, "selector": "*", "qname": f"*._domainkey.{domain}"}]
        key_info = sentinel_hit["public_key"]
        if not key_info.get("present"):
            findings.append(
                f"A wildcard record at *._domainkey.{domain} publishes an empty p= tag, which "
                "revokes every selector. That is the correct way to say 'this domain signs no "
                "mail' — but if it does send mail, none of it can be DKIM-verified."
            )
            checks["key_found"] = True
            return (
                ScanStatus.WARN,
                "A wildcard _domainkey record revokes DKIM for every selector.",
                findings,
                raw,
            )
        findings.append(
            f"A wildcard record at *._domainkey.{domain} answers for every selector, so the "
            "key below applies to all of them and individual selectors cannot be told apart."
        )

    # Nothing found -------------------------------------------------------------
    if not raw["keys"]:
        if explicit:
            names = ", ".join(probe_list)
            message = f"No DKIM key is published at the selector(s) you named: {names}."
            findings.append(message)
            findings.append(
                "Mail from this domain cannot be DKIM-signed with those selectors, so "
                "receivers have nothing to verify the signature against."
            )
            return ScanStatus.FAIL, message, findings, raw

        message = (
            f"No DKIM key found among {len(probe_list)} common selectors — but DKIM "
            "selectors cannot be listed over DNS, so this is not proof that DKIM is missing."
        )
        findings.append(message)
        findings.append(
            "Check a DKIM-Signature header on a real message from this domain for the "
            "s= value, then re-run the scan with that selector."
        )
        # Undeterminable, so scoring drops it rather than counting it as a failure.
        return ScanStatus.ERROR, message, findings, raw

    # At least one key -----------------------------------------------------------
    checks["key_found"] = True
    usable = [k for k in raw["keys"] if k["public_key"].get("valid")]
    revoked = [k for k in raw["keys"] if k["public_key"].get("revoked")]
    checks["key_usable"] = bool(usable)

    for key in revoked:
        findings.append(
            f"Selector '{key['selector']}' publishes an empty p= tag, which revokes the key."
        )
    for key in raw["keys"]:
        error = key["public_key"].get("error")
        if error:
            findings.append(f"Selector '{key['selector']}': {error}")

    testing = [k for k in raw["keys"] if k["testing"]]
    checks["in_testing_mode"] = bool(testing)
    for key in testing:
        findings.append(
            f"Selector '{key['selector']}' is in testing mode (t=y), so receivers are told "
            "to ignore the result of the DKIM check."
        )

    weak: list[str] = []
    strong = False
    for key in usable:
        info = key["public_key"]
        bits = info.get("bits") or 0
        if info.get("type") == "RSA":
            if bits < _MIN_RSA_BITS:
                findings.append(
                    f"Selector '{key['selector']}' uses a {bits}-bit RSA key, which is "
                    "too small to be trusted."
                )
                weak.append(key["selector"])
            elif bits < _RECOMMENDED_RSA_BITS:
                findings.append(
                    f"Selector '{key['selector']}' uses a {bits}-bit RSA key; 2048 bits is "
                    "the current recommendation."
                )
                weak.append(key["selector"])
            else:
                strong = True
        else:
            strong = True
    checks["strong_key"] = strong

    if raw["errors"]:
        findings.append(
            f"{len(raw['errors'])} selector lookup(s) failed, so a key may exist that we "
            "could not read."
        )

    findings = _dedupe(findings)
    found = ", ".join(k["selector"] for k in raw["keys"])

    if not usable:
        return (
            ScanStatus.FAIL,
            f"DKIM records exist ({found}) but none carries a usable public key.",
            findings,
            raw,
        )

    if not explicit:
        findings.append(
            f"Found via a guessed selector ({found}). Other selectors may also be in use — "
            "only the domain owner can confirm the full list."
        )

    if weak or testing or len(usable) < len(raw["keys"]):
        return (
            ScanStatus.WARN,
            f"DKIM is published ({found}) but the configuration is weak.",
            findings,
            raw,
        )

    return ScanStatus.PASS, f"DKIM is published and the key is sound ({found}).", findings, raw


def _dedupe(items: list[str]) -> list[str]:
    """Preserve order, drop repeats — a wildcard makes every selector say the same thing."""
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
