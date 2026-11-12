"""One test per rule, plus the ignore/fail-on bookkeeping."""

import pytest

from aws_r53_healthcheck_audit.model import HealthCheck, Inventory, RecordSet
from aws_r53_healthcheck_audit.rules import (
    CALCULATED_THRESHOLD_UNREACHABLE,
    FAILOVER_WITHOUT_HEALTHCHECK,
    HEALTHCHECK_NO_ALARM,
    HEALTHCHECK_ORPHANED,
    ROUTING_SET_PARTIAL_HEALTHCHECK,
    evaluate,
    should_fail,
    worst_severity,
)

ORPHAN_ID = "22222222-bbbb-4bbb-9bbb-222222222222"
CALC_ID = "33333333-cccc-4ccc-9ccc-333333333333"
EU_ID = "44444444-dddd-4ddd-9ddd-444444444444"


def rules_of(findings):
    return [f.rule for f in findings]


def test_fixture_account_yields_every_rule(inventory):
    findings = evaluate(inventory)
    assert rules_of(findings) == [
        CALCULATED_THRESHOLD_UNREACHABLE,
        FAILOVER_WITHOUT_HEALTHCHECK,
        HEALTHCHECK_ORPHANED,
        ROUTING_SET_PARTIAL_HEALTHCHECK,
        ROUTING_SET_PARTIAL_HEALTHCHECK,
        HEALTHCHECK_NO_ALARM,
    ]
    assert [f.severity for f in findings] == ["high", "high", "medium", "medium", "medium", "low"]


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
    assert len(findings) == 5


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


def _record(name, set_id, hc=None, *, zone="Z1", policy="WEIGHTED", failover=None, **kw):
    return RecordSet(
        zone,
        "example.com.",
        name,
        "A",
        set_identifier=set_id,
        failover=failover,
        health_check_id=hc,
        routing_policy=policy,
        **kw,
    )


def _partial(records):
    inv = Inventory(records=records, alarm_health_check_ids={"hc-1", "hc-2"})
    return [f for f in evaluate(inv) if f.rule == ROUTING_SET_PARTIAL_HEALTHCHECK]


def test_partial_weighted_set_lists_the_unchecked_members(inventory):
    finding = next(
        f for f in evaluate(inventory)
        if f.rule == ROUTING_SET_PARTIAL_HEALTHCHECK and "app.example.com." in f.record
    )
    assert finding.severity == "medium"
    assert finding.resource == "Z1EXAMPLE1111/app.example.com. A WEIGHTED"
    assert finding.references == ["app.example.com. A [app-green]"]
    assert "2 of 3 carry a health check, unchecked: app-green" in finding.detail
    assert "--hosted-zone-id Z1EXAMPLE1111" in finding.remediation


def test_failover_secondary_without_check_is_reported(inventory):
    finding = next(
        f for f in evaluate(inventory)
        if f.rule == ROUTING_SET_PARTIAL_HEALTHCHECK and "api.example.com." in f.record
    )
    assert finding.references == ["api.example.com. A [secondary]"]


def test_uncovered_failover_primary_is_left_to_the_failover_rule():
    findings = _partial(
        [
            _record("x.example.com.", "p", policy="FAILOVER", failover="PRIMARY"),
            _record("x.example.com.", "s", "hc-1", policy="FAILOVER", failover="SECONDARY"),
        ]
    )
    assert findings == []


@pytest.mark.parametrize("policy", ["LATENCY", "GEOLOCATION", "MULTIVALUE", "WEIGHTED"])
def test_partial_set_fires_for_every_routing_policy(policy):
    findings = _partial(
        [
            _record("m.example.com.", "a", "hc-1", policy=policy),
            _record("m.example.com.", "b", policy=policy),
            _record("m.example.com.", "c", policy=policy),
        ]
    )
    assert len(findings) == 1
    assert findings[0].references == ["m.example.com. A [b]", "m.example.com. A [c]"]
    assert policy in findings[0].resource


def test_fully_checked_and_fully_unchecked_sets_are_quiet():
    findings = _partial(
        [
            _record("all.example.com.", "a", "hc-1"),
            _record("all.example.com.", "b", "hc-2"),
            _record("none.example.com.", "a"),
            _record("none.example.com.", "b"),
        ]
    )
    assert findings == []


def test_alias_with_target_health_counts_as_checked():
    alias = dict(is_alias=True, evaluate_target_health=True)
    findings = _partial(
        [
            _record("w.example.com.", "a", "hc-1"),
            _record("w.example.com.", "b", **alias),
            _record("w.example.com.", "c", is_alias=True, evaluate_target_health=False),
        ]
    )
    assert [f.references for f in findings] == [["w.example.com. A [c]"]]


def test_groups_split_by_zone_and_routing_policy():
    findings = _partial(
        [
            _record("g.example.com.", "a", "hc-1", zone="Z1"),
            _record("g.example.com.", "b", zone="Z2"),
            _record("g.example.com.", "c", zone="Z1", policy="LATENCY"),
            _record("g.example.com.", "d", zone="Z1", policy=None),
        ]
    )
    assert findings == []
