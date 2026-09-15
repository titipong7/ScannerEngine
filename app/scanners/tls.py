"""SSL/TLS scanner.

Answers the questions a site owner actually cares about, in order of how much
damage each one does:

1. Does port 443 even answer, and does the certificate **verify** against the
   system trust store (expired / self-signed / wrong hostname / missing
   intermediate)? Any failure here means visitors see a browser warning.
2. **When does the certificate expire?** Warn before it happens, not after.
3. Which **protocol versions** does the server still accept? TLS 1.0/1.1 are
   deprecated (RFC 8996); no TLS 1.2+ at all is a hard failure.
4. Certificate hygiene: key size, signature algorithm, validity period.
5. Is **HSTS** set, so browsers refuse to fall back to plaintext?

Everything is done with the standard library plus `cryptography` (already a
dependency for DNSSEC validation), so there is no openssl binary to shell out
to and nothing extra to install in the container.
"""

from __future__ import annotations

import datetime as dt
import http.client
import logging
import socket
import ssl
import warnings
from typing import Any

import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from app.dns_client import DNSLookupError, resolve
from app.schemas import ScanStatus

logger = logging.getLogger(__name__)

DEFAULT_EXPIRY_WARNING_DAYS = 30
DEFAULT_PORT = 443

# RFC 8996 deprecates TLS 1.0 and 1.1; anything below is long dead.
_DEPRECATED_VERSIONS = ("TLSv1", "TLSv1.1")
_MODERN_VERSIONS = ("TLSv1.2", "TLSv1.3")

_PROBE_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

# Signature algorithms no longer considered collision resistant.
_WEAK_SIGNATURE_HASHES = ("md5", "sha1")

# Browsers reject certificates issued for longer than 398 days.
_MAX_VALIDITY_DAYS = 398


class TLSConnectionError(Exception):
    """Port 443 could not be reached at all."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


def _utc(value: dt.datetime) -> dt.datetime:
    """cryptography returns naive UTC on older versions; normalise either way."""
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _connect(host: str, port: int, timeout: float, *, verify: bool) -> tuple[bytes, dict[str, Any]]:
    """Open one TLS connection and return (DER certificate, negotiated details)."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher() or ("", "", 0)
                return der or b"", {
                    "protocol": tls.version(),
                    "cipher": cipher[0],
                    "cipher_bits": cipher[2],
                    "alpn": tls.selected_alpn_protocol(),
                }
    except ssl.SSLError:
        # SSLError subclasses OSError, so it has to be re-raised before the
        # generic handler below turns a verification failure into "unreachable".
        raise
    except socket.timeout as exc:
        raise TLSConnectionError("timeout", f"Connection to {host}:{port} timed out") from exc
    except ConnectionRefusedError as exc:
        raise TLSConnectionError("refused", f"{host}:{port} refused the connection") from exc
    except socket.gaierror as exc:
        raise TLSConnectionError("dns", f"Could not resolve '{host}': {exc}") from exc
    except OSError as exc:
        raise TLSConnectionError("unreachable", f"Could not reach {host}:{port}: {exc}") from exc


def _probe_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool | None:
    """Can the server speak exactly this version? None = we could not tell.

    The local OpenSSL build may refuse to offer TLS 1.0/1.1 at all, in which
    case a failed handshake says nothing about the *server* — hence the third
    state instead of a misleading False.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            # Probing a deprecated version is the whole point here.
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            # OpenSSL 3 hides legacy ciphers behind security level 0.
            context.set_ciphers("DEFAULT@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.version() is not None
    except ssl.SSLError:
        return False          # server rejected this version — the answer we want
    except (OSError, socket.timeout):
        return None           # network problem, not a verdict


def _public_key_summary(cert: x509.Certificate) -> dict[str, Any]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "bits": key.curve.key_size, "curve": key.curve.name}
    if isinstance(key, dsa.DSAPublicKey):
        return {"type": "DSA", "bits": key.key_size}
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return {"type": type(key).__name__.replace("PublicKey", ""), "bits": 256}
    return {"type": "unknown", "bits": None}


def _subject_alt_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def _name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else None


def _parse_certificate(der: bytes, now: dt.datetime) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    not_before = _utc(cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before)
    not_after = _utc(cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after)
    hash_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

    return {
        "subject": _name_attribute(cert.subject, x509.oid.NameOID.COMMON_NAME),
        "issuer": _name_attribute(cert.issuer, x509.oid.NameOID.ORGANIZATION_NAME)
        or _name_attribute(cert.issuer, x509.oid.NameOID.COMMON_NAME),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "expired": not_after <= now,
        "not_yet_valid": not_before > now,
        "days_until_expiry": round((not_after - now).total_seconds() / 86400, 1),
        "validity_days": round((not_after - not_before).total_seconds() / 86400),
        "signature_hash": hash_name,
        "public_key": _public_key_summary(cert),
        "subject_alt_names": _subject_alt_names(cert),
        "is_self_signed": cert.issuer == cert.subject,
    }


def _check_hsts(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Fetch `/` and read Strict-Transport-Security. Never fatal."""
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl._create_unverified_context())
        conn.request("HEAD", "/", headers={"User-Agent": "ScannerEngine/1.0"})
        response = conn.getresponse()
        header = response.getheader("Strict-Transport-Security")
        conn.close()
    except Exception as exc:  # a site that refuses HEAD must not fail the scan
        logger.debug("HSTS probe failed for %s: %s", host, exc)
        return {"present": False, "error": str(exc)}

    return _parse_hsts(header)


def _parse_hsts(header: str | None) -> dict[str, Any]:
    if not header:
        return {"present": False}

    directives = [d.strip().lower() for d in header.split(";") if d.strip()]
    max_age = next((int(d.split("=", 1)[1]) for d in directives
                    if d.startswith("max-age=") and d.split("=", 1)[1].isdigit()), None)
    return {
        "present": True,
        "header": header,
        "max_age": max_age,
        "include_subdomains": "includesubdomains" in directives,
        "preload": "preload" in directives,
    }


def scan(
    domain: str,
    resolver: dns.resolver.Resolver,
    *,
    port: int = DEFAULT_PORT,
    timeout: float = 8.0,
    warn_days: int = DEFAULT_EXPIRY_WARNING_DAYS,
) -> tuple[ScanStatus, str, list[str], dict[str, Any]]:
    """Return (status, summary, findings, raw_data) for the TLS posture."""
    now = dt.datetime.now(dt.timezone.utc)
    findings: list[str] = []
    raw: dict[str, Any] = {
        "domain": domain,
        "port": port,
        "expiry_warning_days": warn_days,
        "certificate": None,
        "connection": None,
        "protocols": {},
        "hsts": None,
        "checks": {
            "reachable": False,
            "certificate_trusted": False,
            "hostname_matches": False,
            "not_expired": False,
            "expires_soon": False,
            "modern_protocol": False,
            "deprecated_protocols": [],
            "strong_signature": False,
            "hsts": False,
        },
        "errors": [],
    }
    checks = raw["checks"]

    # 0. The domain has to resolve before a socket can be opened at all.
    try:
        resolve(resolver, domain, "A")
    except DNSLookupError as exc:
        if exc.reason == "nxdomain":
            raw["errors"].append({"step": "DNS", "reason": exc.reason, "message": exc.message})
            return ScanStatus.ERROR, exc.message, [exc.message], raw
        # No A record is not fatal — the host may be IPv6 only, so keep going.
        raw["errors"].append({"step": "DNS", "reason": exc.reason, "message": exc.message})

    # 1. Verified handshake: this is what a browser does.
    verify_error: str | None = None
    try:
        der, connection = _connect(domain, port, timeout, verify=True)
        checks["certificate_trusted"] = True
        checks["hostname_matches"] = True
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)
        raw["errors"].append({"step": "verify", "reason": "cert_verify_failed", "message": verify_error})
        # Reconnect without verification so we can still report *why* it failed.
        try:
            der, connection = _connect(domain, port, timeout, verify=False)
        except (TLSConnectionError, ssl.SSLError) as inner:
            message = f"TLS handshake with {domain}:{port} failed: {inner}"
            raw["errors"].append({"step": "connect", "reason": "handshake_failed", "message": message})
            return ScanStatus.FAIL, message, [message], raw
    except ssl.SSLError as exc:
        message = f"TLS handshake with {domain}:{port} failed: {exc}"
        raw["errors"].append({"step": "connect", "reason": "handshake_failed", "message": message})
        return ScanStatus.FAIL, message, [message], raw
    except TLSConnectionError as exc:
        raw["errors"].append({"step": "connect", "reason": exc.reason, "message": exc.message})
        return ScanStatus.ERROR, exc.message, [exc.message], raw

    checks["reachable"] = True
    raw["connection"] = connection

    if verify_error:
        findings.append(f"The certificate is not trusted by browsers: {verify_error}.")

    # 2. Certificate contents.
    if der:
        try:
            certificate = _parse_certificate(der, now)
            raw["certificate"] = certificate
        except Exception as exc:
            raw["errors"].append({"step": "parse", "reason": "parse_failed", "message": str(exc)})
            certificate = None
    else:
        certificate = None

    if certificate:
        checks["not_expired"] = not certificate["expired"] and not certificate["not_yet_valid"]
        days = certificate["days_until_expiry"]

        if certificate["expired"]:
            findings.append(
                f"The certificate expired {abs(days):g} day(s) ago (on {certificate['not_after']}) — "
                "every visitor sees a browser warning."
            )
        elif certificate["not_yet_valid"]:
            findings.append(f"The certificate is not valid until {certificate['not_before']}.")
        elif days <= warn_days:
            checks["expires_soon"] = True
            findings.append(
                f"The certificate expires in {days:g} day(s) (on {certificate['not_after']}). "
                "Renew it before then, or the site starts showing a browser warning."
            )

        if certificate["is_self_signed"]:
            findings.append("The certificate is self-signed, so no browser will trust it.")

        signature_hash = (certificate["signature_hash"] or "").lower()
        checks["strong_signature"] = signature_hash not in _WEAK_SIGNATURE_HASHES
        if not checks["strong_signature"]:
            findings.append(
                f"The certificate is signed with {signature_hash.upper()}, which is no longer "
                "collision resistant and is rejected by modern browsers."
            )

        key = certificate["public_key"]
        if key["type"] == "RSA" and (key["bits"] or 0) < 2048:
            findings.append(f"The RSA key is only {key['bits']} bits; 2048 is the minimum in use today.")
        elif key["type"] == "EC" and (key["bits"] or 0) < 256:
            findings.append(f"The EC key is only {key['bits']} bits; 256 is the minimum in use today.")

        if certificate["validity_days"] > _MAX_VALIDITY_DAYS:
            findings.append(
                f"The certificate is valid for {certificate['validity_days']} days; browsers reject "
                f"anything issued for more than {_MAX_VALIDITY_DAYS} days."
            )

    # 3. Which protocol versions does the server still accept?
    for label, version in _PROBE_VERSIONS.items():
        raw["protocols"][label] = _probe_protocol(domain, port, version, timeout)

    deprecated = [v for v in _DEPRECATED_VERSIONS if raw["protocols"].get(v) is True]
    modern = [v for v in _MODERN_VERSIONS if raw["protocols"].get(v) is True]
    checks["deprecated_protocols"] = deprecated
    # A successful verified handshake already proves a modern version works.
    checks["modern_protocol"] = bool(modern) or connection.get("protocol") in _MODERN_VERSIONS

    if deprecated:
        findings.append(
            f"The server still accepts {' and '.join(deprecated)}, deprecated by RFC 8996. "
            "Disable everything below TLS 1.2."
        )
    if not checks["modern_protocol"]:
        findings.append("The server does not accept TLS 1.2 or 1.3.")
    if raw["protocols"].get("TLSv1.3") is not True and checks["modern_protocol"]:
        findings.append("TLS 1.3 is not enabled; it is faster and drops every legacy cipher.")

    # 4. HSTS.
    hsts = _check_hsts(domain, port, timeout)
    raw["hsts"] = hsts
    checks["hsts"] = bool(hsts.get("present"))
    if not checks["hsts"]:
        findings.append(
            "No Strict-Transport-Security header, so a browser can still be downgraded to "
            "plaintext HTTP on the first visit."
        )
    elif (hsts.get("max_age") or 0) < 15552000:  # 180 days, the preload minimum
        findings.append(
            f"HSTS max-age is only {hsts.get('max_age')} seconds; 15552000 (180 days) is the "
            "recommended minimum."
        )

    # Verdict ------------------------------------------------------------------
    fatal = (
        not checks["certificate_trusted"]
        or not checks["not_expired"]
        or not checks["modern_protocol"]
        or not checks["strong_signature"]
    )
    if fatal:
        return ScanStatus.FAIL, "The TLS configuration would show visitors a browser warning.", findings, raw

    if findings:
        summary = (
            f"TLS works, but the certificate expires in {certificate['days_until_expiry']:g} day(s)."
            if checks["expires_soon"]
            else "TLS works, but the configuration could be hardened."
        )
        return ScanStatus.WARN, summary, findings, raw

    return ScanStatus.PASS, "TLS is correctly configured and the certificate is valid.", findings, raw
