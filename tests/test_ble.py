"""
Unit tests for Termux BLE / Bluetooth acquisition and hybrid fallback subsystem.
"""

import json
from alpha.acquisition.ble import TermuxBleBackend
from alpha.models import SignalType, DataProvenance, FreshnessState


def test_ble_backend_availability():
    backend = TermuxBleBackend()
    status = backend.check_availability()
    assert isinstance(status.available, bool)


def test_ble_hybrid_fallback_mode():
    backend = TermuxBleBackend(enable_hybrid_fallback=True)
    batch = backend.scan(session_id="test_sess_hybrid")
    
    assert batch.metadata.success is True
    assert batch.metadata.item_count > 0
    assert len(batch.observations) > 0
    
    for obs in batch.observations:
        assert obs.signal_type == SignalType.BLE
        assert obs.mac_address is not None
        assert obs.rssi < 0
        assert obs.provenance == DataProvenance.DERIVED


def test_dumpsys_parsing():
    backend = TermuxBleBackend()
    sample_dumpsys = """
    Bluetooth Status: ON
    Bonded devices:
      12:34:56:78:9A:BC (Galaxy Buds2 Pro) [LE]
      DE:AD:BE:EF:00:01 (Sony WH-1000XM5) [BR/EDR]
      12:34:56:78:9A:BC (Duplicate should be skipped)
    Connected devices:
      12:34:56:78:9A:BC (Galaxy Buds2 Pro)
    """
    obs_list = backend._parse_dumpsys_output(sample_dumpsys, "sess_dumpsys")
    assert len(obs_list) == 2
    
    macs = [o.identifier for o in obs_list]
    assert "12:34:56:78:9A:BC" in macs
    assert "DE:AD:BE:EF:00:01" in macs
    
    names = [o.device_name for o in obs_list]
    assert "Galaxy Buds2 Pro" in names
    assert "Sony WH-1000XM5" in names


def test_termux_api_json_parsing(monkeypatch):
    backend = TermuxBleBackend()
    sample_json = json.dumps([
        {"address": "AA:BB:CC:11:22:33", "name": "Apple Watch Ultra", "rssi": -65},
        {"mac": "11:22:33:44:55:66", "device_name": "Smart Band 8", "rssi": -78}
    ])
    
    class DummyProc:
        returncode = 0
        stdout = sample_json
    
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: DummyProc())
    
    obs_list = backend._scan_termux_api("dummy-bin", "sess_api")
    assert len(obs_list) == 2
    assert obs_list[0].mac_address == "AA:BB:CC:11:22:33"
    assert obs_list[0].device_name == "Apple Watch Ultra"
    assert obs_list[0].rssi == -65
    assert obs_list[1].mac_address == "11:22:33:44:55:66"
    assert obs_list[1].device_name == "Smart Band 8"
    assert obs_list[1].rssi == -78
