"""Constant-memory streaming statistics.

Feature extraction previously appended a dict per packet to a list per flow and
computed statistics at the end. For one hour of a busy link that is tens of
millions of dicts resident at once -- the pipeline died of memory exhaustion
long before it produced a CSV.

Every statistic FlowLite reports (mean, standard deviation, variance, min, max,
sum, count) can be maintained incrementally in a fixed number of floats. This
class does that with Welford's online algorithm, which is numerically stable
where the naive "sum of squares minus square of sums" is not: for timestamps
near 1.7e9, the naive form loses all precision and can return a negative
variance.

Standard deviation uses the population convention (``ddof=0``), matching
``numpy.std`` defaults so that values are comparable with the previous release.
"""

from __future__ import annotations

import math

__all__ = ["OnlineStats"]


class OnlineStats:
    """Running count/mean/variance/min/max/sum over a stream of values."""

    __slots__ = ("count", "_mean", "_m2", "_min", "_max", "total")

    def __init__(self) -> None:
        self.count = 0
        self._mean = 0.0
        self._m2 = 0.0
        self._min = math.inf
        self._max = -math.inf
        self.total = 0.0

    def add(self, value: float) -> None:
        value = float(value)
        self.count += 1
        delta = value - self._mean
        self._mean += delta / self.count
        self._m2 += delta * (value - self._mean)
        self.total += value
        if value < self._min:
            self._min = value
        if value > self._max:
            self._max = value

    def merge(self, other: OnlineStats) -> None:
        """Combine another accumulator into this one (parallel aggregation)."""
        if other.count == 0:
            return
        if self.count == 0:
            self.count = other.count
            self._mean = other._mean
            self._m2 = other._m2
            self._min = other._min
            self._max = other._max
            self.total = other.total
            return
        total_count = self.count + other.count
        delta = other._mean - self._mean
        self._mean += delta * other.count / total_count
        self._m2 += other._m2 + delta * delta * self.count * other.count / total_count
        self.count = total_count
        self.total += other.total
        self._min = min(self._min, other._min)
        self._max = max(self._max, other._max)

    @property
    def mean(self) -> float:
        return self._mean if self.count else 0.0

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        # Welford's M2 is non-negative in exact arithmetic; clamp the last ulp.
        return max(0.0, self._m2 / self.count)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def sample_variance(self) -> float:
        if self.count < 2:
            return 0.0
        return max(0.0, self._m2 / (self.count - 1))

    @property
    def minimum(self) -> float:
        return self._min if self.count else 0.0

    @property
    def maximum(self) -> float:
        return self._max if self.count else 0.0

    @property
    def sum(self) -> float:
        return self.total

    def as_tuple(self) -> tuple[float, float, float, float]:
        """``(mean, std, min, max)`` -- the four values most features need."""
        return (self.mean, self.std, self.minimum, self.maximum)

    def __len__(self) -> int:
        return self.count

    def __bool__(self) -> bool:
        return self.count > 0

    def __repr__(self) -> str:
        return (
            f"OnlineStats(n={self.count}, mean={self.mean:.6g}, std={self.std:.6g}, "
            f"min={self.minimum:.6g}, max={self.maximum:.6g})"
        )
