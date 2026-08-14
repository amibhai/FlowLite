"""Shared pytest fixtures."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from flowlite import synth  # noqa: E402
from flowlite.config import load_config  # noqa: E402


@pytest.fixture
def quiet_logger() -> logging.Logger:
    logger = logging.getLogger("flowlite.test")
    logger.handlers = [logging.NullHandler()]
    logger.propagate = False
    logger.setLevel(logging.CRITICAL)
    return logger


@pytest.fixture
def cfg(tmp_path: Path):
    """A valid configuration rooted entirely inside ``tmp_path``."""
    return load_config(
        overrides=[
            f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}",
            "capture.source=folder",
            "capture.folder.stable_seconds=0",
            "capture.folder.poll_interval_s=1",
            "telemetry.enabled=false",
            "device.name=test-device",
        ],
        allow_missing=True,
        _skip_search=True,
    )


@pytest.fixture
def packets():
    return synth.synthetic_session()


@pytest.fixture
def sample_pcap(tmp_path: Path, packets) -> Path:
    return synth.write_pcap(tmp_path / "sample.pcap", packets)


@pytest.fixture
def sample_pcapng(tmp_path: Path, packets) -> Path:
    return synth.write_pcapng(tmp_path / "sample.pcapng", packets)


@pytest.fixture
def flow_rows(sample_pcap, quiet_logger):
    """Flow rows extracted from the sample capture."""
    from flowlite.enrich.geoip import Enricher
    from flowlite.flow.schema import flow_record_to_row
    from flowlite.flow.table import PcapFlowExtractor

    rows = []
    enricher = Enricher()
    extractor = PcapFlowExtractor(logger=quiet_logger)
    extractor.extract(
        sample_pcap,
        lambda record: rows.append(
            flow_record_to_row(
                record, device="test-device", capture_file=sample_pcap.name, enricher=enricher
            )
        ),
    )
    return rows
