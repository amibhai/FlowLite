"""FlowLite -- vendor-neutral network flow telemetry pipeline.

FlowLite turns packets and device counters from *any* network device into tidy,
analysis-ready CSV: per-flow features, per-host behavioural profiles and a
network-wide time series.

Nothing in the core pipeline is vendor-specific and nothing outside the Python
standard library is required to run it. Vendor integrations and accelerators are
optional plugins that FlowLite detects at runtime and degrades around when they
are missing.
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
