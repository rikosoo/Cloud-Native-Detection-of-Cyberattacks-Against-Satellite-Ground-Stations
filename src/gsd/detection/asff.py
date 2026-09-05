"""Map findings to the AWS Security Finding Format consumed by Security Hub."""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any

from gsd.detection.finding import Finding
from gsd.events import to_iso

SCHEMA_VERSION = "2018-10-08"
GENERATOR = "gsd/ground-station-detector"

#: Rule prefix -> ASFF finding type namespace.
TYPE_NAMESPACE = {
    "GS-AUTH": "TTPs/Credential Access",
    "GS-CMD": "TTPs/Impact",
    "GS-RPL": "TTPs/Collection",
    "GS-TLM": "Unusual Behaviors/Application",
    "GS-EXF": "TTPs/Exfiltration",
}


def _namespace(rule_id: str) -> str:
    return TYPE_NAMESPACE.get(rule_id.rsplit("-", 1)[0], "TTPs")


def to_asff(
    finding: Finding,
    *,
    account_id: str | None = None,
    region: str | None = None,
    product_arn: str | None = None,
) -> dict[str, Any]:
    account_id = account_id or os.environ.get("AWS_ACCOUNT_ID", "000000000000")
    region = region or os.environ.get("AWS_REGION", "us-east-1")
    product_arn = product_arn or (
        f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"
    )
    created = to_iso(finding.ts)

    return {
        "SchemaVersion": SCHEMA_VERSION,
        "Id": f"{finding.rule_id}/{finding.event_id}",
        "ProductArn": product_arn,
        "GeneratorId": f"{GENERATOR}/{finding.rule_id}",
        "AwsAccountId": account_id,
        "Types": [f"{_namespace(finding.rule_id)}/{finding.rule_id}"],
        "CreatedAt": created,
        "UpdatedAt": created,
        "FirstObservedAt": created,
        "Severity": {
            "Label": finding.severity.label,
            "Normalized": int(finding.severity),
        },
        "Title": f"[{finding.rule_id}] {finding.title}",
        "Description": finding.description[:1024],
        "SourceUrl": "https://sparta.aerospace.org/",
        "Remediation": {
            "Recommendation": {
                "Text": finding.remediation[:512] or "Review the ground-station runbook.",
                "Url": "https://docs.aws.amazon.com/ground-station/",
            }
        },
        "ProductFields": {
            "gsd/rule_id": finding.rule_id,
            "gsd/technique": finding.technique,
            "gsd/station_id": finding.station_id,
            "gsd/evidence": str(finding.evidence)[:2048],
        },
        "Resources": [
            {
                "Type": "Other",
                "Id": f"groundstation:{finding.station_id}",
                "Region": region,
                "Details": {"Other": {k: str(v)[:1024] for k, v in finding.evidence.items()}},
            }
        ],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
        "VerificationState": "UNKNOWN",
    }


def batch(findings: Iterable[Finding], size: int = 100, **kwargs: Any) -> list[list[dict]]:
    """Chunk findings into BatchImportFindings-sized payloads (100 max per call)."""
    items = [to_asff(f, **kwargs) for f in findings]
    return [items[i : i + size] for i in range(0, len(items), size)]
