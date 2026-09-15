"""Tests for the TLS scanner.

Certificates are generated on the fly and served by a throwaway TLS server on
localhost, so the whole suite is hermetic — no internet, no dependency on some
third party keeping a deliberately-broken test site alive.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.scanners.tls import _connect, _parse_certificate, _parse_hsts

NOW = dt.datetime.now(dt.timezone.utc)


def make_cert(
    common_name: str = "example.test",
    *,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    key_size: int = 2048,
    hash_algorithm=None,
    issuer_name: str | None = None,
) -> tuple[bytes, bytes]:
    """Return (certificate DER, private key PEM)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]) if issuer_name else subject

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - dt.timedelta(days=1))
        .not_valid_after(not_after or NOW + dt.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hash_algorithm or hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.DER), key_pem


# --------------------------------------------------------------------------- #
# Certificate parsing
# --------------------------------------------------------------------------- #
def test_healthy_certificate():
    der, _ = make_cert(not_after=NOW + dt.timedelta(days=90))
    parsed = _parse_certificate(der, NOW)

    assert parsed["expired"] is False
    assert parsed["not_yet_valid"] is False
    assert parsed["days_until_expiry"] == pytest.approx(90, abs=0.1)
    assert parsed["signature_hash"] == "sha256"
    assert parsed["public_key"] == {"type": "RSA", "bits": 2048}
    assert parsed["subject_alt_names"] == ["example.test"]


def test_expired_certificate_reports_negative_countdown():
    der, _ = make_cert(
        not_before=NOW - dt.timedelta(days=100),
        not_after=NOW - dt.timedelta(days=10),
    )
    parsed = _parse_certificate(der, NOW)

    assert parsed["expired"] is True
    assert parsed["days_until_expiry"] == pytest.approx(-10, abs=0.1)


def test_certificate_not_yet_valid():
    der, _ = make_cert(
        not_before=NOW + dt.timedelta(days=5),
        not_after=NOW + dt.timedelta(days=95),
    )
    assert _parse_certificate(der, NOW)["not_yet_valid"] is True


def test_self_signed_is_detected():
    self_signed, _ = make_cert()
    ca_issued, _ = make_cert(issuer_name="Test CA")

    assert _parse_certificate(self_signed, NOW)["is_self_signed"] is True
    assert _parse_certificate(ca_issued, NOW)["is_self_signed"] is False


def test_weak_key_and_validity_period_are_visible():
    der, _ = make_cert(key_size=1024, not_after=NOW + dt.timedelta(days=800))
    parsed = _parse_certificate(der, NOW)

    assert parsed["public_key"]["bits"] == 1024
    assert parsed["validity_days"] > 398


# --------------------------------------------------------------------------- #
# Live handshake against a local server
# --------------------------------------------------------------------------- #
@pytest.fixture
def tls_server(tmp_path):
    """Serve a self-signed certificate on 127.0.0.1 and yield its port."""
    der, key_pem = make_cert("localhost")
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_bytes(
        ssl.DER_cert_to_PEM_cert(der).encode()
    )
    key_file.write_bytes(key_pem)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(client, server_side=True) as tls:
                    tls.recv(1024)
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port, der
    stop.set()
    listener.close()


def test_connect_without_verification_returns_the_certificate(tls_server):
    port, expected_der = tls_server
    der, connection = _connect("localhost", port, timeout=5, verify=False)

    assert der == expected_der
    assert connection["protocol"].startswith("TLSv1.")
    assert connection["cipher_bits"] >= 128


def test_connect_with_verification_rejects_a_self_signed_certificate(tls_server):
    port, _ = tls_server
    with pytest.raises(ssl.SSLCertVerificationError):
        _connect("localhost", port, timeout=5, verify=True)


# --------------------------------------------------------------------------- #
# HSTS header
# --------------------------------------------------------------------------- #
def test_parse_hsts():
    parsed = _parse_hsts("max-age=63072000; includeSubDomains; preload")
    assert parsed == {
        "present": True,
        "header": "max-age=63072000; includeSubDomains; preload",
        "max_age": 63072000,
        "include_subdomains": True,
        "preload": True,
    }


def test_parse_hsts_missing_header():
    assert _parse_hsts(None) == {"present": False}
    assert _parse_hsts("")["present"] is False


def test_parse_hsts_short_max_age():
    parsed = _parse_hsts("max-age=300")
    assert parsed["max_age"] == 300
    assert parsed["include_subdomains"] is False


# --------------------------------------------------------------------------- #
# End-to-end verdict
# --------------------------------------------------------------------------- #
def test_scan_fails_on_an_untrusted_certificate(tls_server, monkeypatch):
    """A self-signed cert must come back as `fail`, not as a connection error."""
    from app.scanners import tls as tls_module

    port, _ = tls_server
    monkeypatch.setattr(tls_module, "resolve", lambda *a, **kw: None)

    status, summary, findings, raw = tls_module.scan(
        "localhost", resolver=None, port=port, timeout=5
    )

    assert status.value == "fail"
    assert raw["checks"]["reachable"] is True
    assert raw["checks"]["certificate_trusted"] is False
    assert any("not trusted by browsers" in f for f in findings)
    assert any("self-signed" in f for f in findings)
    # The certificate itself is still reported, so the dashboard can show details.
    assert raw["certificate"]["subject"] == "localhost"
