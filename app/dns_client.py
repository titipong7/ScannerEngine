"""Thin wrapper around dnspython: resolver construction, lookups, error mapping.

Every DNS failure that is a normal fact about the internet (NXDOMAIN, empty
answer, timeout, broken nameserver) is turned into a `DNSLookupError` carrying a
short machine-readable `reason`, so the scanners never have to catch the full
dnspython exception zoo themselves.
"""

from __future__ import annotations

import logging

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)

# Reasons that mean "the domain itself is unusable" rather than "record missing".
FATAL_REASONS = {"nxdomain", "no_nameservers", "timeout", "dns_error", "invalid_domain"}


class DNSLookupError(Exception):
    """A DNS query could not be answered."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message

    @property
    def fatal(self) -> bool:
        return self.reason in FATAL_REASONS


def normalize_domain(raw: str) -> str:
    """Accept whatever the user pasted and return a bare, lowercase domain."""
    value = (raw or "").strip().lower()
    if not value:
        raise ValueError("domain must not be empty")

    for scheme in ("http://", "https://"):
        if value.startswith(scheme):
            value = value[len(scheme) :]
    value = value.split("/", 1)[0].split("?", 1)[0]
    value = value.split("@")[-1]          # tolerate an email address
    value = value.split(":", 1)[0]        # strip :port
    value = value.rstrip(".")

    if not value or "." not in value or " " in value:
        raise ValueError(f"'{raw}' is not a valid domain name")

    try:
        dns.name.from_text(value)
    except dns.exception.DNSException as exc:  # pragma: no cover - defensive
        raise ValueError(f"'{raw}' is not a valid domain name") from exc

    return value


def build_resolver(
    nameservers: list[str],
    timeout: float,
    lifetime: float,
    *,
    want_dnssec: bool = False,
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    if want_dnssec:
        # DO bit + EDNS0 so the upstream resolver returns RRSIGs and sets AD.
        resolver.use_edns(0, dns.flags.DO, 4096)
    return resolver


def resolve(resolver: dns.resolver.Resolver, qname: str, rdtype: str) -> dns.resolver.Answer:
    """Run one query, translating dnspython exceptions into `DNSLookupError`.

    Whether RRSIGs and the AD flag come back is decided by the resolver: build it
    with `want_dnssec=True` so the DO bit is set on the wire.
    """
    try:
        return resolver.resolve(qname, rdtype, raise_on_no_answer=True)
    except dns.resolver.NXDOMAIN as exc:
        raise DNSLookupError("nxdomain", f"Domain '{qname}' does not exist (NXDOMAIN)") from exc
    except dns.resolver.NoAnswer as exc:
        raise DNSLookupError("no_answer", f"No {rdtype} record found for '{qname}'") from exc
    except dns.resolver.NoNameservers as exc:
        raise DNSLookupError(
            "no_nameservers",
            f"No nameserver could answer the {rdtype} query for '{qname}' "
            "(often a DNSSEC validation failure or a broken zone)",
        ) from exc
    except dns.resolver.LifetimeTimeout as exc:
        raise DNSLookupError("timeout", f"DNS query for {rdtype} '{qname}' timed out") from exc
    except dns.exception.Timeout as exc:
        raise DNSLookupError("timeout", f"DNS query for {rdtype} '{qname}' timed out") from exc
    except dns.exception.DNSException as exc:
        logger.warning("Unexpected DNS failure for %s/%s: %s", qname, rdtype, exc)
        raise DNSLookupError("dns_error", f"DNS error while querying {rdtype} '{qname}': {exc}") from exc


def txt_records(resolver: dns.resolver.Resolver, qname: str) -> list[str]:
    """Return TXT records with their character-strings joined (RFC 7208 §3.3)."""
    answer = resolve(resolver, qname, "TXT")
    records: list[str] = []
    for rdata in answer:
        chunks = [part.decode("utf-8", errors="replace") for part in rdata.strings]
        records.append("".join(chunks).strip())
    return records
