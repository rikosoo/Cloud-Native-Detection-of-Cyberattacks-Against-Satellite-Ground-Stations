"""End-to-end integration test against emulated AWS services.

Everything here exercises the code paths that only ever run in the cloud and are
therefore invisible to the offline pipeline: the Kinesis sink's batching, the
Lambda envelope decoding (both Kinesis records and gzipped CloudWatch Logs
subscriptions), the DynamoDB replay memory's conditional writes, and the ASFF
round trip through ``BatchImportFindings``.

``moto`` intercepts botocore in-process, so no network and no credentials are
involved. Skipped automatically when moto is not installed:

    pip install "moto[server]>=5" && pytest tests/test_integration_aws.py
"""

from __future__ import annotations

import base64
import gzip
import importlib.util
import json
import sys
from pathlib import Path

import pytest

moto = pytest.importorskip("moto", reason="pip install 'moto[server]>=5'")
boto3 = pytest.importorskip("boto3")

from gsd.detection.ml import fit_from_events
from gsd.simulator.scenario import parse_start, run_scenario

REGION = "sa-east-1"
ACCOUNT_ID = "123456789012"
STREAM = "gsd-lab-events"
TABLE = "gsd-lab-replay-memory"
MODEL_BUCKET = "gsd-lab-models"
MODEL_KEY = "models/telemetry.json"
LOG_GROUP = "/ground-station/SENTINEL-GS/events"
MINUTES = 8 * 60

REPO_ROOT = Path(__file__).resolve().parents[1]
DETECTOR_PATH = REPO_ROOT / "infra" / "lambda" / "detector" / "handler.py"


@pytest.fixture
def aws(monkeypatch):
    """Emulated AWS with the stack's resources already provisioned."""
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
        "AWS_ACCOUNT_ID": ACCOUNT_ID,
        "STATE_TABLE": TABLE,
        "MODEL_BUCKET": MODEL_BUCKET,
        "MODEL_KEY": MODEL_KEY,
        "STATION_ID": "SENTINEL-GS",
    }.items():
        monkeypatch.setenv(key, value)

    with moto.mock_aws():
        kinesis = boto3.client("kinesis", region_name=REGION)
        kinesis.create_stream(StreamName=STREAM, ShardCount=1)

        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(
            Bucket=MODEL_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": REGION},
        )

        dynamodb = boto3.client("dynamodb", region_name=REGION)
        dynamodb.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        dynamodb.update_time_to_live(
            TableName=TABLE,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires_at"},
        )

        logs = boto3.client("logs", region_name=REGION)
        logs.create_log_group(logGroupName=LOG_GROUP)

        yield {"kinesis": kinesis, "s3": s3, "dynamodb": dynamodb, "logs": logs}


@pytest.fixture
def scenario():
    # A timeline ending at the present: CloudWatch Logs rejects anything older
    # than 14 days, so a live feed can never use the fixed reproducible date.
    return run_scenario(minutes=MINUTES, start=parse_start(f"{MINUTES}m"))


@pytest.fixture
def uploaded_model(aws):
    """Fit a baseline model and put it where the Lambda expects it."""
    model = fit_from_events(run_scenario(minutes=MINUTES, seed=43, attacks=[]).events)
    aws["s3"].put_object(
        Bucket=MODEL_BUCKET, Key=MODEL_KEY, Body=json.dumps(model.to_dict()).encode()
    )
    return model


def load_detector():
    """Import the Lambda handler fresh, as a cold start would."""
    sys.modules.pop("detector_handler", None)
    spec = importlib.util.spec_from_file_location("detector_handler", DETECTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["detector_handler"] = module
    spec.loader.exec_module(module)
    return module


def all_findings():
    """Every finding in Security Hub -- get_findings caps MaxResults at 100."""
    client = boto3.client("securityhub", region_name=REGION)
    findings, token = [], None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = client.get_findings(**kwargs)
        findings.extend(page["Findings"])
        token = page.get("NextToken")
        if not token:
            return findings


def drain(kinesis, stream=STREAM):
    """Read every record currently on the stream."""
    shard = kinesis.describe_stream(StreamName=stream)["StreamDescription"]["Shards"][0]
    iterator = kinesis.get_shard_iterator(
        StreamName=stream, ShardId=shard["ShardId"], ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    records = []
    for _ in range(50):  # bounded: moto returns everything in a few pages
        page = kinesis.get_records(ShardIterator=iterator, Limit=10_000)
        records.extend(page["Records"])
        iterator = page["NextShardIterator"]
        if not page["Records"]:
            break
    return records


def kinesis_lambda_event(records):
    return {
        "Records": [
            {
                "eventSource": "aws:kinesis",
                "kinesis": {
                    "partitionKey": record["PartitionKey"],
                    "sequenceNumber": record["SequenceNumber"],
                    "data": base64.b64encode(record["Data"]).decode(),
                },
            }
            for record in records
        ]
    }


# --------------------------------------------------------------------------- #
# transport                                                                     #
# --------------------------------------------------------------------------- #


def test_kinesis_sink_publishes_every_event(aws, scenario):
    from gsd.emit.sinks import KinesisSink

    written = KinesisSink(STREAM, region=REGION).emit(scenario.events)
    assert written == len(scenario.events)

    records = drain(aws["kinesis"])
    delivered = [json.loads(line) for r in records for line in r["Data"].decode().splitlines()]
    assert len(delivered) == len(scenario.events)
    assert {d["id"] for d in delivered} == {e.id for e in scenario.events}
    assert {r["PartitionKey"] for r in records} == {"SENTINEL-GS"}


def test_cloudwatch_logs_sink_writes_the_stream(aws, scenario):
    from gsd.emit.sinks import CloudWatchLogsSink

    sink = CloudWatchLogsSink(LOG_GROUP, "integration", region=REGION)
    subset = scenario.events[:400]
    assert sink.emit(subset) == len(subset)

    events = aws["logs"].get_log_events(
        logGroupName=LOG_GROUP, logStreamName="integration", limit=10_000
    )["events"]
    assert len(events) == len(subset)
    assert json.loads(events[0]["message"])["type"] in {
        "telemetry",
        "telecommand",
        "audit",
        "downlink",
    }


def test_cloudwatch_logs_sink_refuses_to_lose_stale_events(aws):
    """PutLogEvents drops >14-day-old records inside a 200 response.

    The reproducible default timeline is months in the past, so this is the
    first thing anyone piping the simulator into a live log group hits. It must
    fail loudly rather than deliver an empty log group and a green exit code.
    """
    from gsd.emit.sinks import CloudWatchLogsSink, RejectedLogEvents

    stale = run_scenario(minutes=60, attacks=[]).events  # fixed 2026-03-12 epoch
    sink = CloudWatchLogsSink(LOG_GROUP, "stale", region=REGION)

    with pytest.raises(RejectedLogEvents, match="14 days"):
        sink.emit(stale)

    assert (
        aws["logs"].get_log_events(logGroupName=LOG_GROUP, logStreamName="stale")["events"] == []
    )


# --------------------------------------------------------------------------- #
# the Lambda                                                                    #
# --------------------------------------------------------------------------- #


def test_detector_lambda_processes_a_kinesis_batch(aws, scenario, uploaded_model):
    from gsd.emit.sinks import KinesisSink

    KinesisSink(STREAM, region=REGION).emit(scenario.events)
    records = drain(aws["kinesis"])

    detector = load_detector()
    result = detector.handler(kinesis_lambda_event(records))

    assert result["processed"] == len(scenario.events)
    assert result["findings"] > 0
    assert result["imported"] == result["findings"]
    assert result["failed"] == 0

    # The findings really landed in Security Hub, in ASFF.
    findings = all_findings()
    assert len(findings) == result["imported"]
    sample = findings[0]
    assert sample["SchemaVersion"] == "2018-10-08"
    assert sample["AwsAccountId"] == ACCOUNT_ID
    assert sample["Severity"]["Label"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFORMATIONAL"}
    assert sample["ProductFields"]["gsd/rule_id"].startswith("GS-")


def test_detector_lambda_decodes_cloudwatch_logs_subscriptions(aws, scenario, uploaded_model):
    """The awslogs envelope: gzipped, base64-wrapped, one message per event."""
    commands = [e for e in scenario.events if e.type == "telecommand"][:50]
    payload = {
        "messageType": "DATA_MESSAGE",
        "logGroup": LOG_GROUP,
        "logStream": "integration",
        "logEvents": [
            {"id": str(i), "timestamp": int(e.ts.timestamp() * 1000), "message": e.to_json()}
            for i, e in enumerate(commands)
        ],
    }
    event = {
        "awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}
    }

    detector = load_detector()
    result = detector.handler(event)
    assert result["processed"] == len(commands)


def test_replay_memory_survives_a_cold_start(aws, scenario, uploaded_model):
    """The rule that cannot work without shared state, proved against DynamoDB.

    The replayed frames sit in the second half of the timeline, so a detector
    that only remembers its own batch would miss them entirely.
    """
    from gsd.emit.sinks import KinesisSink

    KinesisSink(STREAM, region=REGION).emit(scenario.events)
    records = drain(aws["kinesis"])
    half = len(records) // 2

    detector = load_detector()
    first = detector.handler(kinesis_lambda_event(records[:half]))

    detector = load_detector()  # a new execution environment: all local state gone
    second = detector.handler(kinesis_lambda_event(records[half:]))

    assert first["processed"] and second["processed"]

    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    items = table.scan()["Items"]
    assert any(item["pk"].startswith("seq#") for item in items)
    assert any(item["pk"].startswith("mac#") for item in items)
    assert all("expires_at" in item for item in items), "TTL attribute must be set"

    fired = {f["ProductFields"]["gsd/rule_id"] for f in all_findings()}
    assert {"GS-RPL-001", "GS-RPL-002"} <= fired, "replay must be caught across invocations"


def test_guardduty_router_escalates_mission_critical_findings(aws):
    sys.modules.pop("guardduty_handler", None)
    path = REPO_ROOT / "infra" / "lambda" / "guardduty_router" / "handler.py"
    spec = importlib.util.spec_from_file_location("guardduty_handler", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guardduty_handler"] = module
    spec.loader.exec_module(module)

    event = {
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "time": "2026-03-12T03:15:00Z",
        "detail": {
            "id": "finding-1",
            "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            "severity": 5.0,  # MEDIUM on its own
            "title": "API called from a known malicious IP",
            "description": "An API was invoked from a suspicious address.",
            "createdAt": "2026-03-12T03:14:00Z",
            "resource": {
                "instanceDetails": {"tags": [{"key": "role", "value": "uplink"}]},
            },
        },
    }

    result = module.handler(event)
    assert result["escalated"] is True
    assert result["severity"] == "HIGH"  # MEDIUM escalated because it touches the uplink
    assert result["imported"] == 1


def test_detector_lambda_reports_only_the_poison_record(aws, scenario, uploaded_model):
    """One malformed record must not cost the whole batch.

    With ReportBatchItemFailures configured on the event source mapping, the
    handler names the bad sequence number so Lambda retries that record alone,
    and the detections from the rest of the batch still reach Security Hub.
    """
    from gsd.emit.sinks import KinesisSink

    KinesisSink(STREAM, region=REGION).emit(scenario.events)
    records = drain(aws["kinesis"])
    lambda_event = kinesis_lambda_event(records)
    lambda_event["Records"][0]["kinesis"]["data"] = base64.b64encode(b"{not json").decode()

    detector = load_detector()
    result = detector.handler(lambda_event)

    assert result["batchItemFailures"] == [
        {"itemIdentifier": records[0]["SequenceNumber"]}
    ]
    assert result["findings"] > 0
    assert result["imported"] == result["findings"]
