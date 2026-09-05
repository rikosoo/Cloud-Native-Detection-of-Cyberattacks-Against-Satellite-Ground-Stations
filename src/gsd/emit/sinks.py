"""Event sinks.

``file`` and ``stdout`` need nothing but the standard library, so the whole
pipeline runs offline.  ``cloudwatch`` and ``kinesis`` require ``boto3`` and real
credentials; they are imported lazily so the offline path never pays for them.
"""

from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from gsd.events import Event


class Sink(ABC):
    @abstractmethod
    def emit(self, events: Iterable[Event]) -> int:
        """Publish events, returning how many were written."""

    def close(self) -> None:  # pragma: no cover - default no-op
        pass


class StdoutSink(Sink):
    def emit(self, events: Iterable[Event]) -> int:
        count = 0
        for event in events:
            sys.stdout.write(event.to_json() + "\n")
            count += 1
        return count


class FileSink(Sink):
    def __init__(self, path: str) -> None:
        self.path = path

    def emit(self, events: Iterable[Event]) -> int:
        count = 0
        with open(self.path, "w", encoding="utf-8") as fh:
            for event in events:
                fh.write(event.to_json() + "\n")
                count += 1
        return count


class CloudWatchLogsSink(Sink):
    """Ships events to a CloudWatch Logs stream (one JSON document per line).

    A metric filter on the log group turns any finding into a CloudWatch alarm,
    and a subscription filter forwards the same records to the detector Lambda.
    """

    MAX_BATCH = 1000

    def __init__(self, log_group: str, log_stream: str, region: str | None = None) -> None:
        import boto3

        self.client = boto3.client("logs", region_name=region)
        self.log_group = log_group
        self.log_stream = log_stream
        self._ensure_stream()

    def _ensure_stream(self) -> None:
        from botocore.exceptions import ClientError

        for call, kwargs in (
            (self.client.create_log_group, {"logGroupName": self.log_group}),
            (
                self.client.create_log_stream,
                {"logGroupName": self.log_group, "logStreamName": self.log_stream},
            ),
        ):
            try:
                call(**kwargs)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                    raise

    def emit(self, events: Iterable[Event]) -> int:
        batch: list[dict[str, Any]] = []
        written = 0
        for event in events:
            batch.append(
                {"timestamp": int(event.ts.timestamp() * 1000), "message": event.to_json()}
            )
            if len(batch) >= self.MAX_BATCH:
                written += self._flush(batch)
                batch = []
        written += self._flush(batch)
        return written

    def _flush(self, batch: list[dict[str, Any]]) -> int:
        if not batch:
            return 0
        self.client.put_log_events(
            logGroupName=self.log_group,
            logStreamName=self.log_stream,
            logEvents=sorted(batch, key=lambda r: r["timestamp"]),
        )
        return len(batch)


class KinesisSink(Sink):
    """Writes events to a Kinesis data stream, partitioned by station."""

    MAX_BATCH = 500

    def __init__(self, stream_name: str, region: str | None = None) -> None:
        import boto3

        self.client = boto3.client("kinesis", region_name=region)
        self.stream_name = stream_name

    def emit(self, events: Iterable[Event]) -> int:
        records: list[dict[str, Any]] = []
        written = 0
        for event in events:
            records.append(
                {"Data": (event.to_json() + "\n").encode(), "PartitionKey": event.station_id}
            )
            if len(records) >= self.MAX_BATCH:
                written += self._flush(records)
                records = []
        written += self._flush(records)
        return written

    def _flush(self, records: list[dict[str, Any]]) -> int:
        if not records:
            return 0
        self.client.put_records(StreamName=self.stream_name, Records=records)
        return len(records)


def build_sink(target: str, **kwargs: Any) -> Sink:
    """``stdout``, ``file:<path>``, ``cloudwatch:<group>/<stream>``, ``kinesis:<name>``."""
    if target == "stdout":
        return StdoutSink()
    scheme, _, rest = target.partition(":")
    if scheme == "file":
        return FileSink(rest)
    if scheme == "cloudwatch":
        group, _, stream = rest.partition("/")
        return CloudWatchLogsSink(group, stream or "ground-station-sim", **kwargs)
    if scheme == "kinesis":
        return KinesisSink(rest, **kwargs)
    raise ValueError(f"unsupported sink: {target!r}")


def publish_findings(asff_batches: list[list[dict]], region: str | None = None) -> dict[str, int]:
    """Import findings into Security Hub, 100 at a time."""
    import boto3

    client = boto3.client("securityhub", region_name=region)
    imported = failed = 0
    for chunk in asff_batches:
        response = client.batch_import_findings(Findings=chunk)
        imported += response.get("SuccessCount", 0)
        failed += response.get("FailedCount", 0)
    return {"imported": imported, "failed": failed}


def dumps(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str)
