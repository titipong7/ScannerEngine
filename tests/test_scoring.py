"""Tests for the scoring model (pure functions, no network)."""

import pytest

from app.schemas import ScanStatus
from app.scoring import WEIGHTS, components_from_results, grade_for, score


def email_result(spf: str, dmarc: str, overall: str = "warn"):
    return {
        "status": overall,
        "raw_data": {"spf": {"status": spf}, "dmarc": {"status": dmarc}},
    }


def test_everything_passing_is_100_and_an_a():
    result = score(
        {
            "dnssec": {"status": "pass"},
            "tls": {"status": "pass"},
            "email": email_result("pass", "pass", overall="pass"),
        }
    )
    assert result["score"] == 100
    assert result["grade"] == "A"
    # DKIM is not implemented, so the model could only evaluate 90 of 100 points.
    assert result["available_weight"] == 90
    assert result["coverage"] == pytest.approx(0.9, abs=0.001)


def test_everything_failing_is_zero_and_an_f():
    result = score(
        {
            "dnssec": {"status": "fail"},
            "tls": {"status": "fail"},
            "email": email_result("fail", "fail", overall="fail"),
        }
    )
    assert result["score"] == 0
    assert result["grade"] == "F"


def test_warn_is_worth_half_credit():
    result = score({"tls": {"status": "warn"}})
    assert result["score"] == 50
    assert result["components"][0]["credit"] == 0.5


def test_undetermined_components_are_excluded_not_zeroed():
    """A DNS timeout must not be reported as a failing domain."""
    with_error = score({"dnssec": {"status": "error"}, "tls": {"status": "pass"}})
    without = score({"tls": {"status": "pass"}})

    assert with_error["score"] == without["score"] == 100
    assert with_error["undetermined"] == ["dnssec"]
    assert with_error["available_weight"] == WEIGHTS["tls"]


def test_spf_and_dmarc_are_scored_separately():
    components = {c["key"]: c for c in score({"email": email_result("pass", "fail")})["components"]}

    assert components["spf"]["status"] == "pass"
    assert components["dmarc"]["status"] == "fail"
    # 20 of 45 available email points.
    assert score({"email": email_result("pass", "fail")})["score"] == 44


def test_email_falls_back_to_the_overall_status_without_detail():
    """If raw_data is missing, both records inherit the endpoint's verdict."""
    components = components_from_results({"email": {"status": "fail", "raw_data": {}}})
    assert {c.key: c.status for c in components} == {"spf": "fail", "dmarc": "fail"}


def test_no_determinable_component_yields_no_score():
    result = score({"dnssec": {"status": "error"}, "tls": {"status": "error"}})
    assert result["score"] is None
    assert result["grade"] is None
    assert "note" in result


def test_weights_add_up_to_100():
    assert sum(WEIGHTS.values()) == 100


@pytest.mark.parametrize(
    "value,expected",
    [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (70, "C"), (60, "D"), (59, "F"), (0, "F")],
)
def test_grade_boundaries(value, expected):
    assert grade_for(value) == expected


def test_status_enum_is_accepted_as_well_as_its_string():
    assert score({"tls": {"status": ScanStatus.PASS}})["score"] == 100


def test_dkim_is_scored_when_present():
    result = score(
        {
            "dnssec": {"status": "pass"},
            "tls": {"status": "pass"},
            "dkim": {"status": "pass"},
            "email": email_result("pass", "pass", overall="pass"),
        }
    )
    assert result["score"] == 100
    assert result["available_weight"] == 100
    assert result["coverage"] == 1.0


def test_undeterminable_dkim_does_not_cap_the_score():
    """A guessed-selector miss reports `error`; that must not cost the domain points."""
    result = score(
        {
            "dnssec": {"status": "pass"},
            "tls": {"status": "pass"},
            "dkim": {"status": "error"},
            "email": email_result("pass", "pass", overall="pass"),
        }
    )
    assert result["score"] == 100
    assert result["undetermined"] == ["dkim"]
    assert result["coverage"] == pytest.approx(0.9, abs=0.001)
