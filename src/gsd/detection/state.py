"""Cross-batch memory for the replay detectors.

Replay detection is the one rule that cannot be answered from a single batch of
records: the frame being replayed was accepted hours earlier, quite possibly by
another Lambda invocation on another shard.  The engine therefore talks to a
small key/value interface instead of a local dict, so the offline CLI can keep
state in memory while the deployed detector keeps it in DynamoDB with a TTL.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any


class ReplayMemory(ABC):
    """Remembers the first time a (spacecraft, seq) or MAC was accepted."""

    @abstractmethod
    def check_and_record(self, key: str, ts: datetime, ttl_s: int) -> datetime | None:
        """Return the earlier timestamp if ``key`` was already seen, else record it."""


class InMemoryReplayMemory(ReplayMemory):
    def __init__(self) -> None:
        self._seen: dict[str, datetime] = {}

    def check_and_record(self, key: str, ts: datetime, ttl_s: int) -> datetime | None:
        cutoff = ts - timedelta(seconds=ttl_s)
        first_seen = self._seen.get(key)
        if first_seen is not None and first_seen > cutoff:
            return first_seen
        self._seen[key] = ts
        return None


class DynamoDBReplayMemory(ReplayMemory):
    """Conditional-write dedupe table.

    The table needs a single string hash key ``pk`` and TTL enabled on the
    ``expires_at`` attribute, which keeps storage bounded to the replay window.
    """

    def __init__(self, table_name: str, region: str | None = None) -> None:
        import boto3

        self.table = boto3.resource("dynamodb", region_name=region).Table(table_name)

    def check_and_record(self, key: str, ts: datetime, ttl_s: int) -> datetime | None:
        from botocore.exceptions import ClientError

        epoch = int(ts.timestamp())
        item: dict[str, Any] = {
            "pk": key,
            "first_seen": ts.isoformat(),
            "expires_at": epoch + ttl_s,
        }
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) OR expires_at < :now",
                ExpressionAttributeValues={":now": epoch},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            existing = self.table.get_item(Key={"pk": key}).get("Item")
            if existing:
                return datetime.fromisoformat(existing["first_seen"])
        return None
