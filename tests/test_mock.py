"""
Unit tests for mock acquisition backend across scenarios.
"""

import pytest
from alpha.acquisition.mock import MockAcquisitionBackend
from alpha.models import SignalType, FreshnessState


@pytest.mark.parametrize("scenario", ["normal", "busy", "changing", "sparse", "unknown"])
def test_mock_scenarios(scenario):
    backend = MockAcquisitionBackend(scenario=scenario)
    batch = backend.scan("test_mock_sess")

    assert batch.metadata.success is True
    assert batch.metadata.freshness == FreshnessState.LIVE
    assert len(batch.observations) > 0

    # Ensure all observations contain valid MACs and RSSI
    for obs in batch.observations:
        assert obs.rssi < 0
        assert len(obs.mac_address) == 17
        assert obs.provenance.value == "OBSERVED"
