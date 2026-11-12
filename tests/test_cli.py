"""Exit codes and output formats, with the collector swapped for the fixture."""

import csv
import io
import json

import pytest
from botocore.exceptions import ClientError

from aws_r53_healthcheck_audit.cli import main
from aws_r53_healthcheck_audit.collect import collect


@pytest.fixture
def run(inventory, capsys):
    def _run(*argv):
        code = main(list(argv), collector=lambda args: inventory)
        return code, capsys.readouterr()

    return _run


def test_table_output_lists_every_finding(run):
    code, out = run()
    assert code == 1
    assert "SEVERITY" in out.out
    assert "HEALTHCHECK_ORPHANED" in out.out
    assert "6 finding(s)." in out.out
    assert "aws route53 delete-health-check" in out.out


def test_json_output_is_parseable_and_counted(run):
    code, out = run("--format", "json")
    payload = json.loads(out.out)
    assert code == 1
    assert payload["counts"] == {"total": 6, "high": 2, "medium": 3, "low": 1}
    assert payload["findings"][0]["severity"] == "high"


def test_csv_output_has_a_header_and_one_row_per_finding(run):
    code, out = run("--format", "csv")
    rows = list(csv.DictReader(io.StringIO(out.out)))
    assert code == 1
    assert len(rows) == 6
    assert rows[0]["rule"]
    assert rows[0]["remediation"]


def test_fail_on_high_ignores_the_orphan(inventory, capsys):
    only_orphan = type(inventory)(
        health_checks=[hc for hc in inventory.health_checks if hc.id.startswith("22222222")],
        records=[],
        alarm_health_check_ids=set(),
    )
    code = main(["--fail-on", "high"], collector=lambda args: only_orphan)
    assert code == 0
    code = main(["--fail-on", "medium"], collector=lambda args: only_orphan)
    assert code == 1
    assert "HEALTHCHECK_ORPHANED" in capsys.readouterr().out


def test_fail_on_never_always_exits_zero(run):
    code, out = run("--fail-on", "never")
    assert code == 0
    assert "6 finding(s)." in out.out


def test_ignore_affects_the_exit_code(inventory, capsys):
    high_rules = "FAILOVER_WITHOUT_HEALTHCHECK,CALCULATED_THRESHOLD_UNREACHABLE"
    code = main(
        ["--fail-on", "high", "--ignore", high_rules], collector=lambda args: inventory
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "FAILOVER_WITHOUT_HEALTHCHECK" not in out
    assert "4 finding(s)." in out


def test_unknown_rule_name_exits_two(capsys):
    code = main(["--ignore", "NOT_A_RULE"], collector=lambda args: None)
    assert code == 2
    assert "unknown rule(s): NOT_A_RULE" in capsys.readouterr().err


def test_clean_account_exits_zero(inventory, capsys):
    empty = type(inventory)()
    code = main([], collector=lambda args: empty)
    assert code == 0
    assert "No findings" in capsys.readouterr().out


def test_denied_api_call_exits_two_without_a_traceback(denied_route53, capsys):
    route53, cloudwatch = denied_route53
    code = main([], collector=lambda args: collect(route53, cloudwatch))
    err = capsys.readouterr().err
    assert code == 2
    assert "aws error:" in err
    assert "ListHealthChecks" in err


def test_non_aws_exception_is_not_swallowed():
    def boom(args):
        raise RuntimeError("bug in the collector")

    with pytest.raises(RuntimeError):
        main([], collector=boom)


def test_client_error_from_cloudwatch_exits_two(capsys):
    def denied(args):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "cloudwatch:DescribeAlarms denied"}},
            "DescribeAlarms",
        )

    assert main([], collector=denied) == 2
    assert "DescribeAlarms" in capsys.readouterr().err
