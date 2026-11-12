"""The collector joins three APIs; these tests pin the join, offline."""

from aws_r53_healthcheck_audit.collect import bare_zone_id, routing_policy

from .conftest import stubbed_inventory


def test_health_checks_are_flattened(inventory):
    by_id = {hc.id: hc for hc in inventory.health_checks}
    assert len(by_id) == 5
    api = by_id["11111111-aaaa-4aaa-9aaa-111111111111"]
    assert api.type == "HTTPS"
    assert api.target == "api.example.com"
    calc = by_id["33333333-cccc-4ccc-9ccc-333333333333"]
    assert calc.threshold == 3
    assert len(calc.child_ids) == 2


def test_records_carry_their_zone(inventory):
    www = [r for r in inventory.records if r.name == "www.example.com." and r.failover == "PRIMARY"]
    assert len(www) == 1
    assert www[0].zone_id == "Z1EXAMPLE1111"
    assert www[0].zone_name == "example.com."
    assert www[0].health_check_id is None


def test_alias_target_health_is_captured(inventory):
    shop = next(r for r in inventory.records if r.name == "shop.example.com.")
    assert shop.is_alias is True
    assert shop.evaluate_target_health is True


def test_only_route53_health_metric_alarms_count(inventory):
    assert inventory.alarm_health_check_ids == {
        "11111111-aaaa-4aaa-9aaa-111111111111",
        "33333333-cccc-4ccc-9ccc-333333333333",
    }


def test_zone_filter_skips_other_zones(account):
    inventory = stubbed_inventory(account, zone_ids=["Z1EXAMPLE1111"])
    assert {r.zone_id for r in inventory.records} == {"Z1EXAMPLE1111"}


def test_zone_filter_accepts_the_prefixed_form(account):
    inventory = stubbed_inventory(account, zone_ids=["/hostedzone/Z2EXAMPLE2222"])
    assert {r.zone_id for r in inventory.records} == {"Z2EXAMPLE2222"}


def test_bare_zone_id():
    assert bare_zone_id("/hostedzone/Z123") == "Z123"
    assert bare_zone_id("Z123") == "Z123"


def test_records_using_and_parents_of(inventory):
    users = inventory.records_using("44444444-dddd-4ddd-9ddd-444444444444")
    assert [r.name for r in users] == ["eu.internal.example.net."]
    parents = inventory.parents_of("55555555-eeee-4eee-9eee-555555555555")
    assert [p.id for p in parents] == ["33333333-cccc-4ccc-9ccc-333333333333"]


def test_routing_policy_is_captured(inventory):
    policies = {(r.name, r.set_identifier): r.routing_policy for r in inventory.records}
    assert policies[("app.example.com.", "app-green")] == "WEIGHTED"
    assert policies[("api.example.com.", "secondary")] == "FAILOVER"
    assert policies[("edge.example.com.", "edge-calc")] is None


def test_routing_policy_from_raw_fields():
    assert routing_policy({"Weight": 0}) == "WEIGHTED"
    assert routing_policy({"Region": "eu-west-1"}) == "LATENCY"
    assert routing_policy({"GeoLocation": {"CountryCode": "*"}}) == "GEOLOCATION"
    assert routing_policy({"GeoProximityLocation": {"AWSRegion": "us-east-1"}}) == "GEOPROXIMITY"
    assert routing_policy({"CidrRoutingConfig": {"CollectionId": "c", "LocationName": "l"}}) == (
        "IP_BASED"
    )
    assert routing_policy({"Failover": "SECONDARY"}) == "FAILOVER"
    assert routing_policy({"MultiValueAnswer": True}) == "MULTIVALUE"
    assert routing_policy({"MultiValueAnswer": False}) is None
    assert routing_policy({"Name": "simple.example.com.", "Type": "A"}) is None
