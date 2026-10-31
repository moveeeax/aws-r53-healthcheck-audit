#!/usr/bin/env python3
"""Render the audit against the recorded fixture account, with no AWS calls.

    python examples/demo.py          # table
    python examples/demo.py json     # machine-readable
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aws_r53_healthcheck_audit.collect import bare_zone_id  # noqa: E402
from aws_r53_healthcheck_audit.model import HealthCheck, Inventory, RecordSet  # noqa: E402
from aws_r53_healthcheck_audit.report import render  # noqa: E402
from aws_r53_healthcheck_audit.rules import evaluate, should_fail  # noqa: E402

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "account.json"


def load_inventory() -> Inventory:
    """Build an Inventory straight from the recorded API payloads."""
    account = json.loads(FIXTURE.read_text())
    checks = [
        HealthCheck(id=hc["Id"], type=hc["HealthCheckConfig"]["Type"], config=hc["HealthCheckConfig"])
        for hc in account["list_health_checks"]["HealthChecks"]
    ]
    records = []
    for zone in account["list_hosted_zones"]["HostedZones"]:
        zone_id = bare_zone_id(zone["Id"])
        for raw in account["list_resource_record_sets"][zone_id]["ResourceRecordSets"]:
            alias = raw.get("AliasTarget") or {}
            records.append(
                RecordSet(
                    zone_id=zone_id,
                    zone_name=zone["Name"],
                    name=raw["Name"],
                    type=raw["Type"],
                    set_identifier=raw.get("SetIdentifier"),
                    failover=raw.get("Failover"),
                    health_check_id=raw.get("HealthCheckId"),
                    is_alias=bool(alias),
                    evaluate_target_health=bool(alias.get("EvaluateTargetHealth")),
                )
            )
    alarms = set()
    for alarm in account["describe_alarms"]["MetricAlarms"]:
        dimensions = list(alarm.get("Dimensions", []))
        for query in alarm.get("Metrics", []):
            metric = query["MetricStat"]["Metric"]
            if metric["Namespace"] == "AWS/Route53":
                dimensions += metric.get("Dimensions", [])
        if alarm.get("Namespace") not in ("AWS/Route53", None):
            continue
        alarms.update(d["Value"] for d in dimensions if d["Name"] == "HealthCheckId")
    return Inventory(health_checks=checks, records=records, alarm_health_check_ids=alarms)


def main() -> int:
    fmt = sys.argv[1] if len(sys.argv) > 1 else "table"
    findings = evaluate(load_inventory())
    print(render(findings, fmt))
    assert len(findings) == 4, f"fixture should yield 4 findings, got {len(findings)}"
    return 1 if should_fail(findings, "medium") else 0


if __name__ == "__main__":
    raise SystemExit(main())
