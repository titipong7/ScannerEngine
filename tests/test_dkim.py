"""Tests for the DKIM scanner. Every DNS answer is faked, so these are offline."""

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.scanners import dkim


def public_key_tag(key_size: int = 2048) -> str:
    """A base64 SubjectPublicKeyInfo, exactly as the p= tag carries it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size).public_key()
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


def ed25519_tag() -> str:
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


class FakeResolver:
    nameservers = ["1.1.1.1"]


@pytest.fixture
def dns_zone(monkeypatch):
    """Serve TXT records from a dict keyed by query name."""
    zone: dict[str, list[str]] = {}

    def fake_txt_records(_resolver, qname):
        if qname in zone:
            return zone[qname]
        raise dkim.DNSLookupError("nxdomain", f"Domain '{qname}' does not exist (NXDOMAIN)")

    monkeypatch.setattr(dkim, "txt_records", fake_txt_records)
    return zone


# --------------------------------------------------------------------------- #
# The central honesty property
# --------------------------------------------------------------------------- #
def test_guessed_selectors_that_find_nothing_are_undeterminable(dns_zone):
    """Not finding a guessed key proves nothing, so it must not read as a failure."""
    status, summary, findings, raw = dkim.scan("example.com", FakeResolver())

    assert status.value == "error"
    assert "cannot be listed over DNS" in summary
    assert raw["selectors_were_supplied"] is False
    assert any("DKIM-Signature header" in f for f in findings)


def test_named_selectors_that_find_nothing_are_a_failure(dns_zone):
    """If the caller says where the key is, its absence is a real finding."""
    status, summary, _, raw = dkim.scan("example.com", FakeResolver(), selectors=["google"])

    assert status.value == "fail"
    assert "selector(s) you named" in summary
    assert raw["selectors_were_supplied"] is True


# --------------------------------------------------------------------------- #
# Key inspection
# --------------------------------------------------------------------------- #
def test_healthy_2048_bit_key_passes(dns_zone):
    dns_zone["google._domainkey.example.com"] = [f"v=DKIM1; k=rsa; p={public_key_tag()}"]

    status, summary, _, raw = dkim.scan("example.com", FakeResolver(), selectors=["google"])

    assert status.value == "pass"
    assert "key is sound" in summary
    assert raw["keys"][0]["public_key"] == {
        "present": True,
        "valid": True,
        "revoked": False,
        "type": "RSA",
        "bits": 2048,
    }


def test_ed25519_key_is_accepted(dns_zone):
    dns_zone["s1._domainkey.example.com"] = [f"v=DKIM1; k=ed25519; p={ed25519_tag()}"]

    status, _, _, raw = dkim.scan("example.com", FakeResolver(), selectors=["s1"])

    assert status.value == "pass"
    assert raw["keys"][0]["public_key"]["type"] == "Ed25519"


def test_1024_bit_key_warns(dns_zone):
    dns_zone["k1._domainkey.example.com"] = [f"v=DKIM1; p={public_key_tag(1024)}"]

    status, _, findings, _ = dkim.scan("example.com", FakeResolver(), selectors=["k1"])

    assert status.value == "warn"
    assert any("1024-bit RSA" in f for f in findings)


def test_revoked_key_fails(dns_zone):
    dns_zone["google._domainkey.example.com"] = ["v=DKIM1; k=rsa; p="]

    status, summary, findings, _ = dkim.scan("example.com", FakeResolver(), selectors=["google"])

    assert status.value == "fail"
    assert "none carries a usable public key" in summary
    assert any("revokes the key" in f for f in findings)


def test_unparseable_key_fails(dns_zone):
    dns_zone["google._domainkey.example.com"] = ["v=DKIM1; p=!!!not base64!!!"]

    status, _, findings, _ = dkim.scan("example.com", FakeResolver(), selectors=["google"])

    assert status.value == "fail"
    assert any("not valid base64" in f for f in findings)


def test_testing_mode_warns(dns_zone):
    dns_zone["google._domainkey.example.com"] = [f"v=DKIM1; t=y; p={public_key_tag()}"]

    status, _, findings, raw = dkim.scan("example.com", FakeResolver(), selectors=["google"])

    assert status.value == "warn"
    assert raw["checks"]["in_testing_mode"] is True
    assert any("testing mode" in f for f in findings)


# --------------------------------------------------------------------------- #
# Wildcard records
# --------------------------------------------------------------------------- #
def test_wildcard_record_is_reported_once_not_per_selector(dns_zone, monkeypatch):
    """A wildcard answers every selector; 22 identical 'discoveries' would be noise."""

    def wildcard_txt(_resolver, _qname):
        return ["v=DKIM1; p="]

    monkeypatch.setattr(dkim, "txt_records", wildcard_txt)

    status, summary, findings, raw = dkim.scan("example.com", FakeResolver())

    assert status.value == "warn"
    assert raw["wildcard_record"] is True
    assert [key["selector"] for key in raw["keys"]] == ["*"]
    assert len(findings) == 1
    assert "revokes every selector" in findings[0]


def test_wildcard_with_a_real_key_still_reports_the_key(dns_zone, monkeypatch):
    tag = public_key_tag()
    monkeypatch.setattr(dkim, "txt_records", lambda _r, _q: [f"v=DKIM1; p={tag}"])

    status, _, findings, raw = dkim.scan("example.com", FakeResolver())

    assert status.value == "pass"
    assert raw["wildcard_record"] is True
    assert any("answers for every selector" in f for f in findings)


# --------------------------------------------------------------------------- #
# Record parsing
# --------------------------------------------------------------------------- #
def test_parse_dkim_record_tags():
    tags = dkim._parse_dkim_record("v=DKIM1; k=rsa; t=y:s; s=email; p=abc")
    assert tags == {"v": "DKIM1", "k": "rsa", "t": "y:s", "s": "email", "p": "abc"}


def test_multiple_selectors_are_all_probed(dns_zone):
    dns_zone["a._domainkey.example.com"] = [f"v=DKIM1; p={public_key_tag()}"]
    dns_zone["b._domainkey.example.com"] = [f"v=DKIM1; p={public_key_tag(1024)}"]

    status, summary, _, raw = dkim.scan("example.com", FakeResolver(), selectors=["a", "b", "c"])

    assert {key["selector"] for key in raw["keys"]} == {"a", "b"}
    assert status.value == "warn"  # the 1024-bit key drags it down
