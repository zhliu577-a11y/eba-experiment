"""Small dependency-free statistics helpers for experiment reports."""

from __future__ import annotations

import math
import statistics
from collections.abc import Iterable


def percentile(values: Iterable[float], fraction: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("percentile requires at least one value")
    if fraction <= 0:
        return ordered[0]
    if fraction >= 1:
        return ordered[-1]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def summary(values: Iterable[float]) -> dict[str, float | int]:
    samples = [float(value) for value in values]
    if not samples:
        raise ValueError("summary requires at least one sample")
    return {
        "n": len(samples),
        "mean": statistics.fmean(samples),
        "stddev": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "median": statistics.median(samples),
        "p50": percentile(samples, 0.50),
        "p95": percentile(samples, 0.95),
        "p99": percentile(samples, 0.99),
        "min": min(samples),
        "max": max(samples),
    }


def bootstrap_ci(
    values: Iterable[float],
    *,
    iterations: int = 2000,
    confidence: float = 0.95,
    seed: int = 7,
) -> tuple[float, float]:
    import random

    samples = [float(value) for value in values]
    if not samples:
        raise ValueError("bootstrap requires samples")
    rng = random.Random(seed)
    means = [
        statistics.fmean(rng.choice(samples) for _ in range(len(samples))) for _ in range(iterations)
    ]
    alpha = (1 - confidence) / 2
    return percentile(means, alpha), percentile(means, 1 - alpha)
