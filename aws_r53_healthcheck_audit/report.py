"""Table, JSON and CSV renderers for a list of findings."""

from __future__ import annotations

import csv
import io
import json

from .rules import Finding

COLUMNS = ("SEVERITY", "RULE", "RESOURCE", "DETAIL")
CSV_FIELDS = (
    "rule",
    "severity",
    "resource",
    "health_check_id",
    "zone_id",
    "zone_name",
    "record",
    "detail",
    "remediation",
)


def render_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings. Every health check is referenced and alarmed."
    rows = [(f.severity.upper(), f.rule, f.resource, f.detail) for f in findings]
    widths = [
        max(len(COLUMNS[i]), max(len(r[i]) for r in rows)) for i in range(len(COLUMNS) - 1)
    ]
    out = [
        "  ".join(COLUMNS[i].ljust(widths[i]) for i in range(len(widths))) + "  " + COLUMNS[-1]
    ]
    for row in rows:
        head = "  ".join(row[i].ljust(widths[i]) for i in range(len(widths)))
        out.append(f"{head}  {row[-1]}")
    out.append("")
    for f in findings:
        out.append(f"fix {f.resource}:")
        out.append(f"  {f.remediation}")
    out.append("")
    out.append(f"{len(findings)} finding(s).")
    return "\n".join(out)


def render_json(findings: list[Finding]) -> str:
    payload = {
        "findings": [f.as_dict() for f in findings],
        "counts": _counts(findings),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        writer.writerow(f.as_dict())
    return buf.getvalue().rstrip("\r\n")


def _counts(findings: list[Finding]) -> dict:
    counts = {"total": len(findings), "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] += 1
    return counts


def render(findings: list[Finding], fmt: str) -> str:
    if fmt == "json":
        return render_json(findings)
    if fmt == "csv":
        return render_csv(findings)
    return render_table(findings)
