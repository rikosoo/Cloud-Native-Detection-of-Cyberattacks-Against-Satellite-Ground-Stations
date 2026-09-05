"""Correlate GuardDuty findings with ground-station context.

GuardDuty sees the AWS-native half of the attack (anomalous API calls, traffic
to a known-bad address, credential exfiltration) but knows nothing about the
mission: it cannot tell that the instance it just flagged is the uplink gateway.
This function re-scores the finding using the mission asset inventory and pushes
the enriched copy back into Security Hub, so one queue holds both halves of the
picture.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

REGION = os.environ.get("AWS_REGION", "us-east-1")
ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "")
STATION_ID = os.environ.get("STATION_ID", "SENTINEL-GS")

#: Tag value marking assets on the uplink/commanding path.
MISSION_CRITICAL_TAG = os.environ.get("MISSION_CRITICAL_TAG", "uplink")

_securityhub = boto3.client("securityhub", region_name=REGION)

ESCALATION = {"INFORMATIONAL": "LOW", "LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"}


def _is_mission_critical(detail: dict[str, Any]) -> bool:
    resource = detail.get("resource", {})
    tags = resource.get("instanceDetails", {}).get("tags", [])
    if any(t.get("value") == MISSION_CRITICAL_TAG for t in tags):
        return True
    access_key = resource.get("accessKeyDetails", {})
    return access_key.get("userName", "").startswith(("gs-", "svc-"))


def _severity_label(score: float) -> str:
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 1.0:
        return "LOW"
    return "INFORMATIONAL"


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    detail = event.get("detail", {})
    if not detail:
        LOG.warning("event carried no GuardDuty detail: %s", json.dumps(event)[:512])
        return {"imported": 0}

    label = _severity_label(float(detail.get("severity", 0)))
    critical = _is_mission_critical(detail)
    if critical:
        label = ESCALATION.get(label, label)

    created = detail.get("createdAt", event.get("time"))
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": f"guardduty-enriched/{detail.get('id', 'unknown')}",
        "ProductArn": (
            f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default"
        ),
        "GeneratorId": "gsd/guardduty-router",
        "AwsAccountId": ACCOUNT_ID,
        "Types": [f"TTPs/{detail.get('type', 'Unknown')}"],
        "CreatedAt": created,
        "UpdatedAt": event.get("time", created),
        "Severity": {"Label": label},
        "Title": f"[{STATION_ID}] {detail.get('title', 'GuardDuty finding')}",
        "Description": (detail.get("description", ""))[:1024],
        "ProductFields": {
            "gsd/station_id": STATION_ID,
            "gsd/mission_critical": str(critical).lower(),
            "gsd/guardduty_type": detail.get("type", ""),
            "gsd/original_severity": str(detail.get("severity", "")),
        },
        "Resources": [
            {
                "Type": "Other",
                "Id": f"groundstation:{STATION_ID}",
                "Region": REGION,
                "Details": {"Other": {"guardDutyFindingId": str(detail.get("id", ""))}},
            }
        ],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
    }

    response = _securityhub.batch_import_findings(Findings=[finding])
    LOG.info(
        "guardduty %s escalated=%s -> %s (failed=%s)",
        detail.get("type"),
        critical,
        label,
        response.get("FailedCount", 0),
    )
    return {"imported": response.get("SuccessCount", 0), "escalated": critical, "severity": label}
