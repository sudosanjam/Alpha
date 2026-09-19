"""
Unit tests for SQLite database transactions, schema migrations, and indexing.
"""

import tempfile
import time
from pathlib import Path
import pytest
from alpha.models import Session, Observation, Contact, Event, SignalType, ContactState
from alpha.storage.database import AlphaDatabase


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "alpha_test.db"
        db = AlphaDatabase(str(db_path))
        yield db


def test_session_crud(temp_db):
    sess = Session(session_id="sess_123", started_at=time.time(), observation_count=10)
    temp_db.create_session(sess)

    fetched = temp_db.get_session("sess_123")
    assert fetched is not None
    assert fetched.session_id == "sess_123"
    assert fetched.observation_count == 10

    sess.observation_count = 25
    sess.status = "COMPLETED"
    temp_db.update_session(sess)

    updated = temp_db.get_session("sess_123")
    assert updated.observation_count == 25
    assert updated.status == "COMPLETED"


def test_observations_and_contacts_batch_insert(temp_db):
    obs_list = [
        Observation(session_id="sess_1", identifier=f"00:11:22:33:44:{i:02d}", mac_address=f"00:11:22:33:44:{i:02d}", rssi=-50 - i)
        for i in range(10)
    ]
    temp_db.insert_observations(obs_list)
    res_obs = temp_db.get_observations_for_session("sess_1")
    assert len(res_obs) == 10

    contacts_list = [
        Contact(session_id="sess_1", identifier=f"00:11:22:33:44:{i:02d}", mac_address=f"00:11:22:33:44:{i:02d}", state=ContactState.ACTIVE, last_rssi=-60)
        for i in range(10)
    ]
    temp_db.save_contacts(contacts_list)
    res_c = temp_db.get_contacts_for_session("sess_1")
    assert len(res_c) == 10
