import json
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber

from aws_r53_healthcheck_audit.collect import collect

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def account():
    return json.loads((FIXTURES / "account.json").read_text())


def _clients():
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
        region_name="us-east-1",
    )
    return session.client("route53"), session.client("cloudwatch", region_name="us-east-1")


def stubbed_inventory(account, zone_ids=None):
    """Run the real collector against the fixture through botocore's Stubber."""
    route53, cloudwatch = _clients()
    r53_stub, cw_stub = Stubber(route53), Stubber(cloudwatch)

    r53_stub.add_response("list_health_checks", account["list_health_checks"], {})
    r53_stub.add_response("list_hosted_zones", account["list_hosted_zones"], {})
    wanted = [z.rsplit("/", 1)[-1] for z in (zone_ids or [])]
    for zone in account["list_hosted_zones"]["HostedZones"]:
        zone_id = zone["Id"].rsplit("/", 1)[-1]
        if wanted and zone_id not in wanted:
            continue
        r53_stub.add_response(
            "list_resource_record_sets",
            account["list_resource_record_sets"][zone_id],
            {"HostedZoneId": zone_id},
        )
    cw_stub.add_response(
        "describe_alarms", account["describe_alarms"], {"AlarmTypes": ["MetricAlarm"]}
    )

    with r53_stub, cw_stub:
        inventory = collect(route53, cloudwatch, zone_ids=zone_ids)
        r53_stub.assert_no_pending_responses()
        cw_stub.assert_no_pending_responses()
    return inventory


@pytest.fixture
def inventory(account):
    return stubbed_inventory(account)


@pytest.fixture
def denied_route53():
    """A route53 client whose ListHealthChecks is denied."""
    route53, cloudwatch = _clients()
    stub = Stubber(route53)
    stub.add_client_error(
        "list_health_checks",
        service_error_code="AccessDenied",
        service_message="User is not authorized to perform route53:ListHealthChecks",
        http_status_code=403,
    )
    stub.activate()
    return route53, cloudwatch
