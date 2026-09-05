"""Unsupervised baseline model for spacecraft telemetry.

A per-channel threshold only fires once a value crosses an ICD red line -- by
which point the spacecraft is already in trouble.  This model learns the joint
distribution of the housekeeping channels from a clean baseline run and scores
each new sample by its squared Mahalanobis distance, so a *combination* of
individually-legal values (high current at nominal voltage while the amplifier
runs hot) is flagged well before any single limit is breached.

Implementation notes:
  * Robust location/scale (median / MAD) keeps the baseline from being dragged
    by the few outliers a real archive always contains.
  * The covariance is shrunk towards its diagonal (Ledoit-Wolf style, fixed
    intensity) so the inverse stays well conditioned on short baselines.
  * Only numpy is required -- the model serialises to JSON and loads inside a
    Lambda function without a scikit-learn layer.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from gsd.events import TELEMETRY, Event
from gsd.simulator.spacecraft import FEATURE_CHANNELS

SHRINKAGE = 0.15


def vectorise(payload: dict[str, Any], channels: Sequence[str] = FEATURE_CHANNELS) -> np.ndarray:
    return np.array([float(payload.get(c, 0.0)) for c in channels], dtype=float)


@dataclass
class TelemetryModel:
    channels: tuple[str, ...] = FEATURE_CHANNELS
    center: np.ndarray | None = None
    precision: np.ndarray | None = None
    scale: np.ndarray | None = None
    threshold: float = 0.0
    quantile: float = 0.999
    trained_on: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- lifecycle ------------------------------------------------------
    @property
    def is_fitted(self) -> bool:
        return self.center is not None and self.precision is not None

    def fit(self, samples: Iterable[dict[str, Any]]) -> TelemetryModel:
        matrix = np.array([vectorise(s, self.channels) for s in samples], dtype=float)
        if matrix.ndim != 2 or matrix.shape[0] < len(self.channels) + 2:
            raise ValueError("not enough baseline samples to fit the telemetry model")

        center = np.median(matrix, axis=0)
        mad = np.median(np.abs(matrix - center), axis=0)
        scale = np.where(mad > 1e-9, mad * 1.4826, matrix.std(axis=0) + 1e-9)

        standardised = (matrix - center) / scale
        cov = np.cov(standardised, rowvar=False)
        cov = (1 - SHRINKAGE) * cov + SHRINKAGE * np.diag(np.diag(cov) + 1e-6)

        self.center = center
        self.scale = scale
        self.precision = np.linalg.pinv(cov)
        self.trained_on = int(matrix.shape[0])

        scores = np.array([self._score_vector(row) for row in matrix])
        self.threshold = float(np.quantile(scores, self.quantile))
        self.metadata = {
            "baseline_p50": float(np.quantile(scores, 0.5)),
            "baseline_p99": float(np.quantile(scores, 0.99)),
        }
        return self

    # -- scoring --------------------------------------------------------
    def _score_vector(self, vector: np.ndarray) -> float:
        assert self.center is not None and self.precision is not None and self.scale is not None
        delta = (vector - self.center) / self.scale
        return float(delta @ self.precision @ delta)

    def score(self, payload: dict[str, Any]) -> float:
        return self._score_vector(vectorise(payload, self.channels))

    def top_channels(self, payload: dict[str, Any], k: int = 3) -> list[str]:
        """Channels contributing most to the distance, for triage."""
        assert self.center is not None and self.scale is not None
        delta = np.abs((vectorise(payload, self.channels) - self.center) / self.scale)
        order = np.argsort(delta)[::-1][:k]
        return [self.channels[i] for i in order]

    # -- persistence ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        assert self.is_fitted and self.center is not None and self.precision is not None
        assert self.scale is not None
        return {
            "channels": list(self.channels),
            "center": self.center.tolist(),
            "scale": self.scale.tolist(),
            "precision": self.precision.tolist(),
            "threshold": self.threshold,
            "quantile": self.quantile,
            "trained_on": self.trained_on,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> TelemetryModel:
        model = cls(channels=tuple(raw["channels"]), quantile=raw.get("quantile", 0.999))
        model.center = np.array(raw["center"], dtype=float)
        model.scale = np.array(raw["scale"], dtype=float)
        model.precision = np.array(raw["precision"], dtype=float)
        model.threshold = float(raw["threshold"])
        model.trained_on = int(raw.get("trained_on", 0))
        model.metadata = raw.get("metadata", {})
        return model

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> TelemetryModel:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def fit_from_events(events: Iterable[Event], quantile: float = 0.999) -> TelemetryModel:
    """Fit on the nominal telemetry of a baseline run (labelled events excluded)."""
    payloads = [e.payload for e in events if e.type == TELEMETRY and e.truth is None]
    return TelemetryModel(quantile=quantile).fit(payloads)
