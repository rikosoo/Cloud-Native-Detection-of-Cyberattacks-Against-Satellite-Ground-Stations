"""Ground-station detection Lambda.

Triggered by the Kinesis stream that carries ground-station telemetry,
telecommands, audit records and downlink events.  Runs the same
``gsd.detection`` engine used offline, imports the resulting findings into
Security Hub as ASFF, and publishes CloudWatch metrics via embedded metric
format so alarms and dashboards need no extra plumbing.

The ``gsd`` package is provided by a Lambda layer built from ``src/``.
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import os
from collections.abc import Iterator
from typing import Any

import boto3

from gsd.detection.asff import batch as asff_batch
from gsd.detection.engine import DetectionEngine
from gsd.detection.ml import TelemetryModel
from gsd.detection.state import DynamoDBReplayMemory
from gsd.events import Event

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

REGION = os.environ.get("AWS_REGION", "us-east-1")
ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "")
STATE_TABLE = os.environ.get("STATE_TABLE", "")
MODEL_BUCKET = os.environ.get("MODEL_BUCKET", "")
MODEL_KEY = os.environ.get("MODEL_KEY", "models/telemetry.json")
METRIC_NAMESPACE = os.environ.get("METRIC_NAMESPACE", "GroundStation/Detection")

_securityhub = boto3.client("securityhub", region_name=REGION)
_s3 = boto3.client("s3", region_name=REGION)

# Cached across warm invocations: loading the baseline model costs an S3 GET.
_MODEL: TelemetryModel | None = None
_ENGINE: DetectionEngine | None = None


def _load_model() -> TelemetryModel | None:
    global _MODEL
    if _MODEL is None and MODEL_BUCKET:
        body = _s3.get_object(Bucket=MODEL_BUCKET, Key=MODEL_KEY)["Body"].read()
        _MODEL = TelemetryModel.from_dict(json.loads(body))
        LOG.info("loaded telemetry model trained on %s samples", _MODEL.trained_on)
    return _MODEL


def _engine() -> DetectionEngine:
    """One engine per execution environment.

    Rate and streak state is per-container, which is acceptable: shards are
    sticky and the replay memory -- the only state that must be globally
    consistent -- lives in DynamoDB.
    """
    global _ENGINE
    if _ENGINE is None:
        kwargs: dict[str, Any] = {"model": _load_model()}
        if STATE_TABLE:
            kwargs["replay_memory"] = DynamoDBReplayMemory(STATE_TABLE, region=REGION)
        _ENGINE = DetectionEngine(**kwargs)
    return _ENGINE


def _decode(event: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield raw event documents from Kinesis or a CloudWatch Logs subscription."""
    if "awslogs" in event:  # CloudWatch Logs subscription filter
        raw = gzip.decompress(base64.b64decode(event["awslogs"]["data"]))
        for log_event in json.loads(raw).get("logEvents", []):
            yield json.loads(log_event["message"])
        return

    for record in event.get("Records", []):
        payload = record.get("kinesis", {}).get("data")
        if payload is None:  # SQS / direct invoke
            payload_text = record.get("body", json.dumps(record))
        else:
            payload_text = base64.b64decode(payload).decode("utf-8")
        for line in payload_text.splitlines():
            if line.strip():
                yield json.loads(line)


def _emit_metrics(findings: list[Any], processed: int) -> None:
    """Embedded metric format: CloudWatch turns these log lines into metrics."""
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.label] = by_severity.get(finding.severity.label, 0) + 1

    document = {
        "_aws": {
            "Timestamp": int(__import__("time").time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": METRIC_NAMESPACE,
                    "Dimensions": [["StationId"]],
                    "Metrics": [
                        {"Name": "EventsProcessed", "Unit": "Count"},
                        {"Name": "FindingsEmitted", "Unit": "Count"},
                        {"Name": "CriticalFindings", "Unit": "Count"},
                    ],
                }
            ],
        },
        "StationId": os.environ.get("STATION_ID", "SENTINEL-GS"),
        "EventsProcessed": processed,
        "FindingsEmitted": len(findings),
        "CriticalFindings": by_severity.get("CRITICAL", 0),
        "SeverityBreakdown": by_severity,
    }
    print(json.dumps(document))


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    engine = _engine()
    events = [Event.from_dict(doc) for doc in _decode(event)]
    findings = engine.run(events)

    imported = failed = 0
    if findings and ACCOUNT_ID:
        for chunk in asff_batch(findings, account_id=ACCOUNT_ID, region=REGION):
            response = _securityhub.batch_import_findings(Findings=chunk)
            imported += response.get("SuccessCount", 0)
            failed += response.get("FailedCount", 0)
            for failure in response.get("FailedFindings", []):
                LOG.error("failed finding %s: %s", failure.get("Id"), failure.get("ErrorMessage"))

    _emit_metrics(findings, len(events))
    LOG.info(
        "processed=%s findings=%s imported=%s failed=%s rules=%s",
        len(events),
        len(findings),
        imported,
        failed,
        sorted({f.rule_id for f in findings}),
    )
    return {
        "processed": len(events),
        "findings": len(findings),
        "imported": imported,
        "failed": failed,
    }
