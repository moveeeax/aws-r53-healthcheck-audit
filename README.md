# aws-r53-healthcheck-audit

[![ci](https://github.com/moveeeax/aws-r53-healthcheck-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-r53-healthcheck-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%E2%80%93%203.15-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Joins Route 53 health checks to the record sets and CloudWatch alarms that reference them, and
reports both directions of the mismatch: checks that bill for nothing, and failover records that
can never fail over.

The console lists health checks and record sets on separate screens and never joins them. So an
orphaned check keeps costing money and reporting green into nothing, and a `FAILOVER` primary with
no `HealthCheckId` leaves the secondary as decoration. This reads both sides once and prints the
remediation command.

## Rules

| Rule | Severity | Fires when |
| --- | --- | --- |
| `FAILOVER_WITHOUT_HEALTHCHECK` | high | a `FAILOVER` `PRIMARY` record carries no `HealthCheckId` (and is not an alias with `EvaluateTargetHealth`) |
| `CALCULATED_THRESHOLD_UNREACHABLE` | high | a `CALCULATED` check's `HealthThreshold` exceeds its `ChildHealthChecks` count, so it can never be healthy |
| `ROUTING_SET_PARTIAL_HEALTHCHECK` | medium | in a weighted, latency, geolocation, geoproximity, IP-based, multivalue or failover set (same zone, name, type and routing policy), some records are checked and others are not; Route 53 treats the unchecked ones as always healthy. Alias records with `EvaluateTargetHealth` count as checked. An unchecked failover `PRIMARY` is left to `FAILOVER_WITHOUT_HEALTHCHECK`, so in a failover pair this flags an unchecked `SECONDARY` |
| `HEALTHCHECK_ORPHANED` | medium | no record set, no calculated parent and no CloudWatch alarm reference the check |
| `HEALTHCHECK_NO_ALARM` | low | records use the check but nothing alarms on its `HealthCheckStatus` |

## How it works

Three reads, one join, no writes:

1. `ListHealthChecks` (paginated) for every check and its config.
2. `ListHostedZones` plus `ListResourceRecordSets` per zone for every record, with its
   `HealthCheckId`, alias target and routing policy (read from `Weight`, `Region`, `GeoLocation`,
   `GeoProximityLocation`, `CidrRoutingConfig`, `Failover` or `MultiValueAnswer`).
3. `DescribeAlarms` for metric alarms over `AWS/Route53` / `HealthCheckStatus`, including alarms
   that reach the metric through metric math (`Metrics[].MetricStat`).

Then each health check is reported once with the records that reference it, and each unprotected
failover record once with its zone - a check shared by ten records is one finding listing ten
references, not ten findings. A routing set with unchecked members is one finding listing them.

Route 53 is global, so there is no `--region` for the Route 53 calls. Health-check metrics are
published in `us-east-1`, which is where alarms are read from unless `--alarm-region` says
otherwise.

## Install

```bash
pip install git+https://github.com/moveeeax/aws-r53-healthcheck-audit
```

Needs `route53:ListHealthChecks`, `route53:ListHostedZones`, `route53:ListResourceRecordSets` and
`cloudwatch:DescribeAlarms`.

## Usage

```bash
aws-r53-healthcheck-audit
aws-r53-healthcheck-audit --format json --fail-on high
aws-r53-healthcheck-audit --zone Z123456ABCDEF --ignore HEALTHCHECK_NO_ALARM
aws-r53-healthcheck-audit --profile prod --alarm-region us-east-1 --format csv
```

Against the recorded fixture account in `examples/`:

```
$ aws-r53-healthcheck-audit
SEVERITY  RULE                              RESOURCE                                        DETAIL
HIGH      CALCULATED_THRESHOLD_UNREACHABLE  33333333-cccc-4ccc-9ccc-333333333333            calculated check needs 3 healthy children but has 2 - it can never report healthy
HIGH      FAILOVER_WITHOUT_HEALTHCHECK      Z1EXAMPLE1111/www.example.com. A [www-primary]  FAILOVER PRIMARY record www.example.com. A [www-primary] in zone example.com. carries no HealthCheckId, so Route 53 can never fail over to the secondary
MEDIUM    HEALTHCHECK_ORPHANED              22222222-bbbb-4bbb-9bbb-222222222222            HTTP health check for blog-old.example.com (198.51.100.14) is referenced by no record set, no calculated check and no CloudWatch alarm - it bills for nothing
MEDIUM    ROUTING_SET_PARTIAL_HEALTHCHECK   Z1EXAMPLE1111/api.example.com. A FAILOVER       FAILOVER records api.example.com. A in zone example.com.: 1 of 2 carry a health check, unchecked: secondary - Route 53 treats an unchecked record as always healthy and keeps answering with it when its endpoint is down
MEDIUM    ROUTING_SET_PARTIAL_HEALTHCHECK   Z1EXAMPLE1111/app.example.com. A WEIGHTED       WEIGHTED records app.example.com. A in zone example.com.: 2 of 3 carry a health check, unchecked: app-green - Route 53 treats an unchecked record as always healthy and keeps answering with it when its endpoint is down
LOW       HEALTHCHECK_NO_ALARM              44444444-dddd-4ddd-9ddd-444444444444            health check for eu.example.com is used by 1 record set(s) but has no CloudWatch alarm in us-east-1 - a flip to unhealthy pages nobody

fix 22222222-bbbb-4bbb-9bbb-222222222222:
  aws route53 delete-health-check --health-check-id 22222222-bbbb-4bbb-9bbb-222222222222
...

6 finding(s).
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--profile` | - | AWS profile |
| `--zone` | all zones | hosted zone id, repeatable; accepts `Z123` or `/hostedzone/Z123` |
| `--alarm-region` | `us-east-1` | where health-check alarms are read from |
| `--format` | `table` | `table`, `json` or `csv` |
| `--fail-on` | `medium` | lowest severity that exits 1; `never` always exits 0 |
| `--ignore` | - | comma-separated rules dropped from output and exit code |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | no findings at or above `--fail-on` |
| 1 | at least one finding at or above `--fail-on` |
| 2 | AWS API, credential or usage error (the message, not a traceback) |

So in CI:

```yaml
- name: Route 53 health-check audit
  run: aws-r53-healthcheck-audit --fail-on high --format json
```

## Examples

`examples/demo.py` runs the full rule set against `tests/fixtures/account.json` with no AWS calls
and no credentials - useful for seeing the output shape or diffing a rule change:

```bash
python examples/demo.py          # table, exits 1
python examples/demo.py json     # machine-readable
```

`examples/sample-output.txt` and `examples/sample-output.json` are that output, committed.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

Tests run offline: every AWS response comes from `tests/fixtures/account.json` through botocore's
`Stubber`, including a denied `ListHealthChecks` that must exit 2.

## License

MIT
