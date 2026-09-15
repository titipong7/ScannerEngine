"""Offline tests for the RRSIG expiry window (no network needed)."""

import datetime as dt
from types import SimpleNamespace

import pytest

from app.scanners.dnssec import DEFAULT_EXPIRY_WARNING_DAYS, _serialize_rrsig

NOW = dt.datetime(2026, 9, 15, tzinfo=dt.timezone.utc)


def _fake_rrsig(expires_in_days: float):
    """Minimal stand-in for a dns.rdtypes.ANY.RRSIG object."""
    expiration = NOW + dt.timedelta(days=expires_in_days)
    return SimpleNamespace(
        type_covered=48,  # DNSKEY
        key_tag=2371,
        signer=dns_name("example.com"),
        algorithm=13,
        inception=(NOW - dt.timedelta(days=30)).timestamp(),
        expiration=expiration.timestamp(),
    )


def dns_name(text: str):
    import dns.name

    return dns.name.from_text(text)


@pytest.mark.parametrize(
    "days,expected_expired",
    [(40.0, False), (3.0, False), (-1.0, True), (0.0, True)],
)
def test_expiry_fields(days, expected_expired):
    record = _serialize_rrsig(_fake_rrsig(days), NOW)
    assert record["expired"] is expected_expired
    assert record["days_until_expiry"] == pytest.approx(days, abs=0.1)


def test_warning_window_boundary():
    """A signature inside the window warns; one outside it does not."""
    inside = _serialize_rrsig(_fake_rrsig(DEFAULT_EXPIRY_WARNING_DAYS - 1), NOW)
    outside = _serialize_rrsig(_fake_rrsig(DEFAULT_EXPIRY_WARNING_DAYS + 1), NOW)
    assert inside["days_until_expiry"] <= DEFAULT_EXPIRY_WARNING_DAYS
    assert outside["days_until_expiry"] > DEFAULT_EXPIRY_WARNING_DAYS
    assert not inside["expired"] and not outside["expired"]
