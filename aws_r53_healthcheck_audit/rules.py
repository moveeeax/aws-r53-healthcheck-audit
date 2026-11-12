"""The five findings this tool reports, plus severity bookkeeping."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .model import HealthCheck, Inventory, RecordSet

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

HEALTHCHECK_ORPHANED = "HEALTHCHECK_ORPHANED"
FAILOVER_WITHOUT_HEALTHCHECK = "FAILOVER_WITHOUT_HEALTHCHECK"
CALCULATED_THRESHOLD_UNREACHABLE = "CALCULATED_THRESHOLD_UNREACHABLE"
HEALTHCHECK_NO_ALARM = "HEALTHCHECK_NO_ALARM"
ROUTING_SET_PARTIAL_HEALTHCHECK = "ROUTING_SET_PARTIAL_HEALTHCHECK"

ALL_RULES = (
    HEALTHCHECK_ORPHANED,
    FAILOVER_WITHOUT_HEALTHCHECK,
    CALCULATED_THRESHOLD_UNREACHABLE,
    HEALTHCHECK_NO_ALARM,
    ROUTING_SET_PARTIAL_HEALTHCHECK,
)

RULE_SEVERITY = {
    HEALTHCHECK_ORPHANED: "medium",
    FAILOVER_WITHOUT_HEALTHCHECK: "high",
    CALCULATED_THRESHOLD_UNREACHABLE: "high",
    HEALTHCHECK_NO_ALARM: "low",
    ROUTING_SET_PARTIAL_HEALTHCHECK: "medium",
}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    resource: str
    detail: str
    remediation: str
    health_check_id: str = ""
    zone_id: str = ""
    zone_name: str = ""
    record: str = ""
    references: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _delete_command(check: HealthCheck) -> str:
    return f"aws route53 delete-health-check --health-check-id {check.id}"


def _attach_command(record: RecordSet) -> str:
    return (
        f"aws route53 change-resource-record-sets --hosted-zone-id {record.zone_id} "
        "--change-batch '{\"Changes\":[{\"Action\":\"UPSERT\",\"ResourceRecordSet\":"
        f'{{"Name":"{record.name}","Type":"{record.type}",'
        f'"SetIdentifier":"{record.set_identifier or "primary"}","Failover":"PRIMARY",'
        '"HealthCheckId":"<health-check-id>","TTL":60,'
        '"ResourceRecords":[{"Value":"<current-value>"}]}}]}\''
    )


def _alarm_command(check: HealthCheck, region: str) -> str:
    return (
        f"aws cloudwatch put-metric-alarm --region {region} "
        f"--alarm-name r53-healthcheck-{check.id} --namespace AWS/Route53 "
        f"--metric-name HealthCheckStatus --dimensions Name=HealthCheckId,Value={check.id} "
        "--statistic Minimum --period 60 --evaluation-periods 2 --threshold 1 "
        "--comparison-operator LessThanThreshold --treat-missing-data breaching"
    )


def _orphaned(inv: Inventory) -> list[Finding]:
    findings = []
    for check in inv.health_checks:
        if inv.records_using(check.id):
            continue
        if check.id in inv.alarm_health_check_ids:
            continue
        if inv.parents_of(check.id):
            # A child of a calculated check is consumed, just not by a record.
            continue
        findings.append(
            Finding(
                rule=HEALTHCHECK_ORPHANED,
                severity=RULE_SEVERITY[HEALTHCHECK_ORPHANED],
                resource=check.id,
                detail=(
                    f"{check.type} health check for {check.target} is referenced by no record "
                    "set, no calculated check and no CloudWatch alarm - it bills for nothing"
                ),
                remediation=_delete_command(check),
                health_check_id=check.id,
            )
        )
    return findings


def _failover_unprotected(inv: Inventory) -> list[Finding]:
    findings = []
    for record in inv.records:
        if (record.failover or "").upper() != "PRIMARY" or record.covered:
            # An alias with EvaluateTargetHealth needs no HealthCheckId.
            continue
        findings.append(
            Finding(
                rule=FAILOVER_WITHOUT_HEALTHCHECK,
                severity=RULE_SEVERITY[FAILOVER_WITHOUT_HEALTHCHECK],
                resource=f"{record.zone_id}/{record.label}",
                detail=(
                    f"FAILOVER PRIMARY record {record.label} in zone {record.zone_name} carries "
                    "no HealthCheckId, so Route 53 can never fail over to the secondary"
                ),
                remediation=_attach_command(record),
                zone_id=record.zone_id,
                zone_name=record.zone_name,
                record=record.label,
            )
        )
    return findings


def _calculated_unreachable(inv: Inventory) -> list[Finding]:
    findings = []
    for check in inv.health_checks:
        if check.type != "CALCULATED":
            continue
        threshold, children = check.threshold, check.child_ids
        if threshold is None or threshold <= len(children):
            continue
        findings.append(
            Finding(
                rule=CALCULATED_THRESHOLD_UNREACHABLE,
                severity=RULE_SEVERITY[CALCULATED_THRESHOLD_UNREACHABLE],
                resource=check.id,
                detail=(
                    f"calculated check needs {threshold} healthy children but has "
                    f"{len(children)} - it can never report healthy"
                ),
                remediation=(
                    f"aws route53 update-health-check --health-check-id {check.id} "
                    f"--health-threshold {len(children)}"
                ),
                health_check_id=check.id,
                references=list(children),
            )
        )
    return findings


def _missing_alarm(inv: Inventory) -> list[Finding]:
    findings = []
    for check in inv.health_checks:
        users = inv.records_using(check.id)
        if not users or check.id in inv.alarm_health_check_ids:
            continue
        findings.append(
            Finding(
                rule=HEALTHCHECK_NO_ALARM,
                severity=RULE_SEVERITY[HEALTHCHECK_NO_ALARM],
                resource=check.id,
                detail=(
                    f"health check for {check.target} is used by {len(users)} record set(s) but "
                    f"has no CloudWatch alarm in {inv.alarm_region} - a flip to unhealthy pages "
                    "nobody"
                ),
                remediation=_alarm_command(check, inv.alarm_region),
                health_check_id=check.id,
                references=[r.label for r in users],
            )
        )
    return findings


def _partial_routing_set(inv: Inventory) -> list[Finding]:
    """Route 53 treats a record with no health check as always healthy.

    Records answer as one group when they share zone, name, type and routing policy. If some
    members are checked and others are not, the unchecked ones keep getting traffic when their
    endpoint is down. An uncovered FAILOVER PRIMARY is FAILOVER_WITHOUT_HEALTHCHECK's finding,
    so in a failover group only the secondary is listed here.
    """
    groups: dict[tuple, list[RecordSet]] = {}
    for record in inv.records:
        if record.routing_policy:
            key = (record.zone_id, record.name, record.type, record.routing_policy)
            groups.setdefault(key, []).append(record)

    findings = []
    for (zone_id, name, rtype, policy), members in groups.items():
        if all(r.covered for r in members) or not any(r.covered for r in members):
            continue
        uncovered = [
            r
            for r in members
            if not r.covered
            and not (policy == "FAILOVER" and (r.failover or "").upper() == "PRIMARY")
        ]
        if not uncovered:
            continue
        ids = ", ".join(r.set_identifier or "-" for r in uncovered)
        findings.append(
            Finding(
                rule=ROUTING_SET_PARTIAL_HEALTHCHECK,
                severity=RULE_SEVERITY[ROUTING_SET_PARTIAL_HEALTHCHECK],
                resource=f"{zone_id}/{name} {rtype} {policy}",
                detail=(
                    f"{policy} records {name} {rtype} in zone {members[0].zone_name}: "
                    f"{len(members) - len(uncovered)} of {len(members)} carry a health check, "
                    f"unchecked: {ids} - Route 53 treats an unchecked record as always "
                    "healthy and keeps answering with it when its endpoint is down"
                ),
                remediation=(
                    f"aws route53 change-resource-record-sets --hosted-zone-id {zone_id} "
                    "--change-batch file://health-checks.json  # UPSERT the unchecked records "
                    f"({ids}) with a HealthCheckId added (alias records: set "
                    "AliasTarget.EvaluateTargetHealth to true instead)"
                ),
                zone_id=zone_id,
                zone_name=members[0].zone_name,
                record=f"{name} {rtype}",
                references=[r.label for r in uncovered],
            )
        )
    return findings


def evaluate(inventory: Inventory, ignore: set[str] | None = None) -> list[Finding]:
    """Run every rule not named in `ignore`, worst severity first."""
    skip = {r.strip().upper() for r in (ignore or set()) if r.strip()}
    findings: list[Finding] = []
    for rule, run in (
        (HEALTHCHECK_ORPHANED, _orphaned),
        (FAILOVER_WITHOUT_HEALTHCHECK, _failover_unprotected),
        (CALCULATED_THRESHOLD_UNREACHABLE, _calculated_unreachable),
        (HEALTHCHECK_NO_ALARM, _missing_alarm),
        (ROUTING_SET_PARTIAL_HEALTHCHECK, _partial_routing_set),
    ):
        if rule in skip:
            continue
        findings.extend(run(inventory))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule, f.resource))
    return findings


def worst_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "never" or not findings:
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[f.severity] >= threshold for f in findings)
