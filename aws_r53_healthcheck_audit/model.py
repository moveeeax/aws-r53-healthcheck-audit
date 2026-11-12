"""Inventory types shared by the collector and the rules."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HealthCheck:
    """One Route 53 health check, flattened out of its config."""

    id: str
    type: str
    config: dict = field(default_factory=dict, repr=False)

    @property
    def target(self) -> str:
        """A human label for the thing the check watches."""
        fqdn = self.config.get("FullyQualifiedDomainName")
        ip = self.config.get("IPAddress")
        if fqdn and ip:
            return f"{fqdn} ({ip})"
        if fqdn:
            return fqdn
        if ip:
            return ip
        if self.type == "CALCULATED":
            return f"calculated over {len(self.child_ids)} children"
        if self.type == "CLOUDWATCH_METRIC":
            alarm = self.config.get("AlarmIdentifier", {}).get("Name", "")
            return f"cloudwatch alarm {alarm}".strip()
        return "-"

    @property
    def child_ids(self) -> list[str]:
        return list(self.config.get("ChildHealthChecks") or [])

    @property
    def threshold(self) -> int | None:
        value = self.config.get("HealthThreshold")
        return None if value is None else int(value)


@dataclass(frozen=True)
class RecordSet:
    """One resource record set, with the zone it lives in."""

    zone_id: str
    zone_name: str
    name: str
    type: str
    set_identifier: str | None = None
    failover: str | None = None
    health_check_id: str | None = None
    is_alias: bool = False
    evaluate_target_health: bool = False
    routing_policy: str | None = None

    @property
    def covered(self) -> bool:
        """Route 53 can tell whether this record is healthy."""
        return bool(self.health_check_id) or (self.is_alias and self.evaluate_target_health)

    @property
    def label(self) -> str:
        if self.set_identifier:
            return f"{self.name} {self.type} [{self.set_identifier}]"
        return f"{self.name} {self.type}"


@dataclass
class Inventory:
    """Everything one audit run needs, already joined by id."""

    health_checks: list[HealthCheck] = field(default_factory=list)
    records: list[RecordSet] = field(default_factory=list)
    alarm_health_check_ids: set[str] = field(default_factory=set)
    alarm_region: str = "us-east-1"

    def records_using(self, health_check_id: str) -> list[RecordSet]:
        return [r for r in self.records if r.health_check_id == health_check_id]

    def parents_of(self, health_check_id: str) -> list[HealthCheck]:
        """Calculated checks that list this check as a child."""
        return [hc for hc in self.health_checks if health_check_id in hc.child_ids]
