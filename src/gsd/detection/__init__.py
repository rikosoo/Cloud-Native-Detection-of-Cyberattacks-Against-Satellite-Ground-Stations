"""Detection layer: deterministic rules plus a multivariate telemetry model."""

from gsd.detection.engine import DetectionEngine
from gsd.detection.finding import Finding, Severity

__all__ = ["DetectionEngine", "Finding", "Severity"]
