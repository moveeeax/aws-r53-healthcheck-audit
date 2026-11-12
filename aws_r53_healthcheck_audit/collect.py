"""Read health checks, record sets and health-check alarms out of one account."""

from __future__ import annotations

from .model import HealthCheck, Inventory, RecordSet

ROUTE53_NAMESPACE = "AWS/Route53"
HEALTH_CHECK_METRIC = "HealthCheckStatus"
HEALTH_CHECK_DIMENSION = "HealthCheckId"


def bare_zone_id(zone_id: str) -> str:
    """`/hostedzone/Z123` and `Z123` are the same zone."""
    return zone_id.rsplit("/", 1)[-1]


# ResourceRecordSet field that marks each non-simple routing policy.
ROUTING_POLICY_FIELDS = (
    ("Weight", "WEIGHTED"),
    ("Region", "LATENCY"),
    ("GeoLocation", "GEOLOCATION"),
    ("GeoProximityLocation", "GEOPROXIMITY"),
    ("CidrRoutingConfig", "IP_BASED"),
    ("Failover", "FAILOVER"),
    ("MultiValueAnswer", "MULTIVALUE"),
)


def routing_policy(raw: dict) -> str | None:
    """The record's routing policy, or None for a simple record."""
    for key, policy in ROUTING_POLICY_FIELDS:
        value = raw.get(key)
        if value is not None and value is not False:
            return policy
    return None


def health_checks(route53) -> list[HealthCheck]:
    found: list[HealthCheck] = []
    for page in route53.get_paginator("list_health_checks").paginate():
        for raw in page.get("HealthChecks", []):
            config = raw.get("HealthCheckConfig", {})
            found.append(
                HealthCheck(
                    id=raw["Id"],
                    type=config.get("Type", "UNKNOWN"),
                    config=config,
                )
            )
    return found


def record_sets(route53, zone_ids: list[str] | None = None) -> list[RecordSet]:
    wanted = {bare_zone_id(z) for z in zone_ids} if zone_ids else None
    found: list[RecordSet] = []
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            zone_id = bare_zone_id(zone["Id"])
            if wanted is not None and zone_id not in wanted:
                continue
            found.extend(_zone_records(route53, zone_id, zone.get("Name", zone_id)))
    return found


def _zone_records(route53, zone_id: str, zone_name: str) -> list[RecordSet]:
    pages = route53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zone_id)
    records: list[RecordSet] = []
    for page in pages:
        for raw in page.get("ResourceRecordSets", []):
            alias = raw.get("AliasTarget") or {}
            records.append(
                RecordSet(
                    zone_id=zone_id,
                    zone_name=zone_name,
                    name=raw.get("Name", ""),
                    type=raw.get("Type", ""),
                    set_identifier=raw.get("SetIdentifier"),
                    failover=raw.get("Failover"),
                    health_check_id=raw.get("HealthCheckId"),
                    is_alias=bool(alias),
                    evaluate_target_health=bool(alias.get("EvaluateTargetHealth")),
                    routing_policy=routing_policy(raw),
                )
            )
    return records


def alarm_health_check_ids(cloudwatch) -> set[str]:
    """Ids of health checks watched by a CloudWatch alarm on HealthCheckStatus."""
    ids: set[str] = set()
    pages = cloudwatch.get_paginator("describe_alarms").paginate(AlarmTypes=["MetricAlarm"])
    for page in pages:
        for alarm in page.get("MetricAlarms", []):
            ids.update(_alarm_targets(alarm))
    return ids


def _alarm_targets(alarm: dict) -> set[str]:
    """A health-check alarm is either a plain metric alarm or metric-math over one."""
    ids: set[str] = set()
    if _is_health_metric(alarm.get("Namespace"), alarm.get("MetricName")):
        ids.update(_dimension_ids(alarm.get("Dimensions", [])))
    for query in alarm.get("Metrics", []) or []:
        stat = (query.get("MetricStat") or {}).get("Metric") or {}
        if _is_health_metric(stat.get("Namespace"), stat.get("MetricName")):
            ids.update(_dimension_ids(stat.get("Dimensions", [])))
    return ids


def _is_health_metric(namespace: str | None, metric: str | None) -> bool:
    return namespace == ROUTE53_NAMESPACE and metric == HEALTH_CHECK_METRIC


def _dimension_ids(dimensions: list[dict]) -> set[str]:
    return {
        d["Value"]
        for d in dimensions
        if d.get("Name") == HEALTH_CHECK_DIMENSION and d.get("Value")
    }


def collect(route53, cloudwatch, zone_ids=None, alarm_region="us-east-1") -> Inventory:
    """One pass over Route 53 and CloudWatch, joined into an Inventory."""
    return Inventory(
        health_checks=health_checks(route53),
        records=record_sets(route53, zone_ids),
        alarm_health_check_ids=alarm_health_check_ids(cloudwatch),
        alarm_region=alarm_region,
    )
