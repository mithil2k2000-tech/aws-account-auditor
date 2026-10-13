"""What a check reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered, so findings can be sorted and filtered with < and >=."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {names})") from None


@dataclass(frozen=True)
class Finding:
    check: str
    severity: Severity
    resource: str
    region: str
    message: str
    remediation: str
    # Rough monthly cost of leaving it as it is, in USD, where that means
    # something (an idle volume). An estimate from list prices, not a bill.
    monthly_cost_usd: float | None = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data
