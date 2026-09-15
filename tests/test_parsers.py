"""Offline unit tests for the parsing/normalisation logic (no network needed).

    pip install pytest && pytest
"""

import pytest

from app.dns_client import normalize_domain
from app.scanners.email_auth import _parse_dmarc, _parse_spf


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://Example.COM/path?a=1", "example.com"),
        ("user@Example.org", "example.org"),
        ("example.net:8080", "example.net"),
        ("example.com.", "example.com"),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "not a domain", "localhost"])
def test_normalize_domain_rejects_garbage(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_parse_spf_counts_only_lookup_mechanisms():
    parsed = _parse_spf("v=spf1 a mx include:_spf.example.com ip4:192.0.2.0/24 ~all")
    assert parsed["all_qualifier"] == "~"
    assert parsed["all_policy"] == "softfail"
    assert parsed["includes"] == ["_spf.example.com"]
    # a + mx + include = 3; "all" and the ip4 mechanism cost nothing.
    assert parsed["dns_lookup_count"] == 3


def test_parse_spf_bare_all_is_a_pass_qualifier():
    assert _parse_spf("v=spf1 all")["all_qualifier"] == "+"


def test_parse_dmarc_tags():
    parsed = _parse_dmarc("v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:a@example.com; adkim=s")
    assert parsed["policy"] == "reject"
    assert parsed["subdomain_policy"] == "none"
    assert parsed["percentage"] == 50
    assert parsed["aggregate_reports"] == ["mailto:a@example.com"]
    assert parsed["alignment_dkim"] == "s"
    assert parsed["alignment_spf"] == "r"  # default when unset
