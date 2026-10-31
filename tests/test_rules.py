"""One test per rule, plus the ignore/fail-on bookkeeping."""

import pytest

from aws_r53_healthcheck_audit.model import HealthCheck, Inventory, RecordSet
from aws_r53_healthcheck_audit.rules import (
    CALCULATED_THRESHOLD_UNREACHABLE,
    FAILOVER_WITHOUT_HEALTHCHECK,
    HEALTHCHECK_NO_ALARM,
    HEALTHCHECK_ORPHANED,
    evaluate,
    should_fail,
    worst_severity,
)

ORPHAN_ID = "22222222-bbbb-4bbb-9bbb-222222222222"
CALC_ID = "33333333-cccc-4ccc-9ccc-333333333333"
EU_ID = "44444444-dddd-4ddd-9ddd-444444444444"


def rules_of(findings):
    return [f.rule for f in findings]


def test_fixture_account_yields_one_finding_per_rule(inventory):
    findings = evaluate(inventory)
    assert rules_of(findings) == [
        CALCULATED_THRESHOLD_UNREACHABLE,
        FAILOVER_WITHOUT_HEALTHCHECK,
        HEALTHCHECK_ORPHANED,
        HEALTHCHECK_NO_ALARM,
    ]
    assert [f.severity for f in findings] == ["high", "high", "medium", "low"]


def test_orphan_names_the_check_and_its_fqdn(inventory):
    orphan = next(f for f in evaluate(inventory) if f.rule == HEALTHCHECK_ORPHANED)
    assert orphan.health_check_id == ORPHAN_ID
    assert "blog-old.example.com" in orphan.detail
    assert orphan.remediation == f"aws route53 delete-health-check --health-check-id {ORPHAN_ID}"


def test_unprotected_failover_names_zone_and_record(inventory):
    finding = next(f for f in evaluate(inventory) if f.rule == FAILOVER_WITHOUT_HEALTHCHECK)
    assert finding.zone_name == "example.com."
    assert "www.example.com." in finding.record
    assert "change-resource-record-sets" in finding.remediation
    assert "--hosted-zone-id Z1EXAMPLE1111" in finding.remediation


def test_alias_failover_with_target_health_is_not_a_finding(inventory):
    reported = {f.record for f in evaluate(inventory)}
    assert not any("shop.example.com." in r for r in reported)


def test_calculated_threshold_above_children(inventory):
    finding = next(f for f in evaluate(inventory) if f.rule == CALCULATED_THRESHOLD_UNREACHABLE)
    assert finding.health_check_id == CALC_ID
    assert "needs 3 healthy children but has 2" in finding.detail
    assert "--health-threshold 2" in finding.remediation


def test_missing_alarm_only_for_referenced_checks(inventory):
    finding = next(f for f in evaluate(inventory) if f.rule == HEALTHCHECK_NO_ALARM)
    assert finding.health_check_id == EU_ID
    assert finding.references == ["eu.internal.example.net. A [eu]"]
    assert "put-metric-alarm" in finding.remediation
    assert "--region us-east-1" in finding.remediation


def test_child_of_calculated_check_is_not_orphaned(inventory):
    orphans = {f.health_check_id for f in evaluate(inventory) if f.rule == HEALTHCHECK_ORPHANED}
    assert "55555555-eeee-4eee-9eee-555555555555" not in orphans


def test_shared_check_is_reported_once():
    check = HealthCheck(
        id="hc-shared",
        type="HTTPS",
        config={"Type": "HTTPS", "FullyQualifiedDomainName": "shared.example.com"},
    )
    records = [
        RecordSet("Z1", "example.com.", f"n{i}.example.com.", "A", health_check_id="hc-shared")
        for i in range(10)
    ]
    findings = evaluate(Inventory(health_checks=[check], records=records))
    assert rules_of(findings) == [HEALTHCHECK_NO_ALARM]
    assert len(findings[0].references) == 10


def test_clean_account_has_no_findings():
    check = HealthCheck(
        id="hc-ok",
        type="HTTPS",
        config={"Type": "HTTPS", "FullyQualifiedDomainName": "ok.example.com"},
    )
    records = [
        RecordSet(
            "Z1",
            "example.com.",
            "ok.example.com.",
            "A",
            set_identifier="primary",
            failover="PRIMARY",
            health_check_id="hc-ok",
        ),
        RecordSet(
            "Z1",
            "example.com.",
            "ok.example.com.",
            "A",
            set_identifier="secondary",
            failover="SECONDARY",
            health_check_id="hc-ok",
        ),
    ]
    inv = Inventory(health_checks=[check], records=records, alarm_health_check_ids={"hc-ok"})
    findings = evaluate(inv)
    assert findings == []
    assert worst_severity(findings) is None
    assert should_fail(findings, "low") is False


def test_ignore_drops_a_rule(inventory):
    findings = evaluate(inventory, ignore={"HEALTHCHECK_NO_ALARM"})
    assert HEALTHCHECK_NO_ALARM not in rules_of(findings)
    assert len(findings) == 3


def test_ignore_is_case_insensitive(inventory):
    findings = evaluate(inventory, ignore={"healthcheck_orphaned"})
    assert HEALTHCHECK_ORPHANED not in rules_of(findings)


@pytest.mark.parametrize(
    "fail_on,expected",
    [("high", False), ("medium", True), ("low", True), ("never", False)],
)
def test_fail_on_threshold_against_a_lone_orphan(inventory, fail_on, expected):
    findings = [f for f in evaluate(inventory) if f.rule == HEALTHCHECK_ORPHANED]
    assert worst_severity(findings) == "medium"
    assert should_fail(findings, fail_on) is expected


def test_calculated_check_at_threshold_is_fine():
    check = HealthCheck(
        id="hc-calc",
        type="CALCULATED",
        config={"Type": "CALCULATED", "HealthThreshold": 2, "ChildHealthChecks": ["a", "b"]},
    )
    records = [RecordSet("Z1", "example.com.", "e.example.com.", "A", health_check_id="hc-calc")]
    inv = Inventory(health_checks=[check], records=records, alarm_health_check_ids={"hc-calc"})
    assert evaluate(inv) == []
