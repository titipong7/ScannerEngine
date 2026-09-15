"""Turn scanner verdicts into a 0-100 score and an A-F grade.

Design decisions worth knowing before you change the weights:

* **Weights reflect blast radius, not effort.** A broken certificate or a
  missing DMARC policy hurts real users; a missing HSTS header is a hardening
  gap. The weights below are the opinionated part of this file — everything
  else is arithmetic.
* **SPF and DMARC are scored separately** even though one endpoint produces
  both, because a domain can easily get one right and the other wrong.
* **`error` is not zero.** If a DNS timeout stopped us from checking DNSSEC,
  scoring it as 0 would tell the user their domain is broken when we simply do
  not know. Components we could not determine are dropped and the remaining
  weights are renormalised, so the score always means "out of what we could
  actually check". `coverage` reports how much of the total weight that was.
* **Modules that do not exist yet** (DKIM) are simply absent from the input,
  which the same renormalisation handles — no placeholder zeros.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from app.schemas import ScanStatus

# How much each component contributes when every module is present.
WEIGHTS: dict[str, int] = {
    "dnssec": 30,
    "dmarc": 25,
    "spf": 20,
    "tls": 15,
    "dkim": 10,
}

LABELS: dict[str, str] = {
    "dnssec": "DNSSEC",
    "dmarc": "DMARC",
    "spf": "SPF",
    "tls": "SSL/TLS",
    "dkim": "DKIM",
}

# A warn is worth half credit: the control exists but does not protect fully.
STATUS_CREDIT: dict[ScanStatus, float | None] = {
    ScanStatus.PASS: 1.0,
    ScanStatus.WARN: 0.5,
    ScanStatus.FAIL: 0.0,
    ScanStatus.ERROR: None,   # undeterminable — excluded from the denominator
}

# Lower bound of each grade.
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


@dataclass(frozen=True)
class Component:
    """One scored line item on the dashboard."""

    key: str
    label: str
    status: str
    weight: int
    credit: float | None      # None when the status could not be determined
    points: float             # credit * weight, 0.0 when undetermined

    @property
    def counted(self) -> bool:
        return self.credit is not None


def grade_for(score: int) -> str:
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"


def _as_status(value: Any) -> ScanStatus | None:
    if isinstance(value, ScanStatus):
        return value
    try:
        return ScanStatus(str(value))
    except ValueError:
        return None


def components_from_results(results: dict[str, dict[str, Any]]) -> list[Component]:
    """Map raw scanner output onto scoreable components.

    `results` is keyed by scan type (`dnssec`, `email`, `tls`) and each value
    holds at least `status`, plus `raw_data` for the email scan, which carries
    the separate SPF and DMARC verdicts.
    """
    statuses: dict[str, ScanStatus | None] = {}

    if "dnssec" in results:
        statuses["dnssec"] = _as_status(results["dnssec"].get("status"))

    if "tls" in results:
        statuses["tls"] = _as_status(results["tls"].get("status"))

    if "email" in results:
        raw = results["email"].get("raw_data") or {}
        overall = _as_status(results["email"].get("status"))
        # Fall back to the combined verdict if the per-record detail is absent.
        statuses["spf"] = _as_status((raw.get("spf") or {}).get("status")) or overall
        statuses["dmarc"] = _as_status((raw.get("dmarc") or {}).get("status")) or overall

    components: list[Component] = []
    for key, status in statuses.items():
        if status is None:
            continue
        credit = STATUS_CREDIT[status]
        weight = WEIGHTS[key]
        components.append(
            Component(
                key=key,
                label=LABELS[key],
                status=status.value,
                weight=weight,
                credit=credit,
                points=(credit or 0.0) * weight,
            )
        )
    return sorted(components, key=lambda c: -c.weight)


def score(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Return the overall score, grade and per-component breakdown."""
    components = components_from_results(results)
    counted = [c for c in components if c.counted]

    available_weight = sum(c.weight for c in counted)
    earned = sum(c.points for c in counted)
    total_weight = sum(WEIGHTS.values())

    if available_weight == 0:
        return {
            "score": None,
            "grade": None,
            "coverage": 0.0,
            "earned_weight": 0.0,
            "available_weight": 0,
            "total_weight": total_weight,
            "components": [asdict(c) for c in components],
            "undetermined": [c.key for c in components if not c.counted],
            "note": "No component could be determined, so no score was produced.",
        }

    value = round(100 * earned / available_weight)
    return {
        "score": value,
        "grade": grade_for(value),
        # How much of the full model we were able to evaluate (1.0 = everything).
        "coverage": round(available_weight / total_weight, 3),
        "earned_weight": round(earned, 2),
        "available_weight": available_weight,
        "total_weight": total_weight,
        "components": [asdict(c) for c in components],
        "undetermined": [c.key for c in components if not c.counted],
    }
