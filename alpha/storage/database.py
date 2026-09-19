"""
SQLite Database Manager for Alpha.

Provides transactional, parameterized persistence in WAL mode for sessions,
observations, temporal contacts, structured events, baselines, and configuration.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from alpha.models import (
    Observation,
    Contact,
    Event,
    BaselineSnapshot,
    Session,
    ContactState,
    DeviceCategory,
    SignalType,
    SignalCategory,
    EventSeverity,
    DataProvenance,
)
from alpha.sanitizer import sanitize_string
from alpha.logger import get_logger

import contextlib

logger = get_logger("storage")


class AlphaDatabase:
    """Manages SQLite storage operations with WAL mode, parameterized queries, and indexes."""

    def __init__(self, db_path: str = "alpha.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextlib.contextmanager
    def _get_connection(self):
        """Create and configure a SQLite connection, ensuring it is closed on exit."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA busy_timeout = 5000")
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Create all required tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            
            # Sessions Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    started_at REAL NOT NULL,
                    ended_at REAL,
                    device_model TEXT,
                    android_version TEXT,
                    termux_version TEXT,
                    alpha_version TEXT,
                    is_mock INTEGER DEFAULT 0,
                    scenario TEXT,
                    observation_count INTEGER DEFAULT 0,
                    contact_count INTEGER DEFAULT 0,
                    event_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'RUNNING'
                )
            """)

            # Observations Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    source TEXT,
                    signal_type TEXT NOT NULL,
                    interface TEXT,
                    identifier TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    ssid TEXT,
                    bssid TEXT,
                    device_name TEXT,
                    rssi INTEGER NOT NULL,
                    frequency INTEGER,
                    channel INTEGER,
                    band TEXT,
                    security TEXT,
                    capabilities TEXT,
                    manufacturer TEXT,
                    oui TEXT,
                    raw_metadata TEXT,
                    scan_age_seconds REAL DEFAULT 0,
                    is_cached INTEGER DEFAULT 0,
                    provenance TEXT DEFAULT 'OBSERVED',
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Contacts Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                    contact_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    signal_type TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    bssid TEXT,
                    ssid TEXT,
                    device_name TEXT,
                    manufacturer TEXT,
                    oui TEXT,
                    is_randomized_mac INTEGER DEFAULT 0,
                    category TEXT DEFAULT 'UNKNOWN',
                    confidence REAL DEFAULT 0.0,
                    classification_reason TEXT,
                    evidence TEXT,
                    state TEXT DEFAULT 'NEW',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    observation_count INTEGER DEFAULT 1,
                    last_rssi INTEGER NOT NULL,
                    min_rssi INTEGER NOT NULL,
                    max_rssi INTEGER NOT NULL,
                    mean_rssi REAL NOT NULL,
                    rssi_variance REAL DEFAULT 0.0,
                    rssi_trend TEXT DEFAULT 'STEADY',
                    signal_category TEXT DEFAULT 'UNKNOWN',
                    channel INTEGER,
                    frequency INTEGER,
                    band TEXT,
                    security TEXT,
                    capabilities TEXT,
                    is_watchlist_match INTEGER DEFAULT 0,
                    watchlist_tags TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Events Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    related_identifier TEXT,
                    related_contact_id TEXT,
                    message TEXT NOT NULL,
                    evidence TEXT,
                    data TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Baselines Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    baseline_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    duration_seconds REAL DEFAULT 0.0,
                    observation_count INTEGER DEFAULT 0,
                    contact_count INTEGER DEFAULT 0,
                    wifi_count INTEGER DEFAULT 0,
                    ble_count INTEGER DEFAULT 0,
                    channel_distribution TEXT,
                    manufacturer_distribution TEXT,
                    security_distribution TEXT,
                    mean_rssi REAL DEFAULT 0.0
                )
            """)

            # Watchlists Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS watchlists (
                    rule_id TEXT PRIMARY KEY,
                    target_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    label TEXT NOT NULL,
                    severity TEXT DEFAULT 'INFO',
                    created_at REAL NOT NULL,
                    enabled INTEGER DEFAULT 1
                )
            """)

            # Signatures Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    signature_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    confidence REAL DEFAULT 0.8,
                    rules_json TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1
                )
            """)

            # OUI Prefixes Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS oui_prefixes (
                    prefix TEXT PRIMARY KEY,
                    manufacturer TEXT NOT NULL
                )
            """)

            # Create Indexes for fast querying
            cur.execute("CREATE INDEX IF NOT EXISTS idx_obs_session_ts ON observations (session_id, timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_obs_identifier ON observations (identifier)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_contacts_session ON contacts (session_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_contacts_identifier ON contacts (identifier)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_contacts_state ON contacts (state)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events (session_id, timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type)")
            
            conn.commit()

    # --- Session Operations ---

    def create_session(self, session: Session) -> None:
        """Insert a new monitoring session."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (
                    session_id, started_at, ended_at, device_model, android_version,
                    termux_version, alpha_version, is_mock, scenario,
                    observation_count, contact_count, event_count, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.started_at,
                    session.ended_at,
                    session.device_model,
                    session.android_version,
                    session.termux_version,
                    session.alpha_version,
                    1 if session.is_mock else 0,
                    session.scenario,
                    session.observation_count,
                    session.contact_count,
                    session.event_count,
                    session.status,
                )
            )
            conn.commit()

    def update_session(self, session: Session) -> None:
        """Update session end time, counts, and status."""
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE sessions SET
                    ended_at = ?,
                    observation_count = ?,
                    contact_count = ?,
                    event_count = ?,
                    status = ?
                WHERE session_id = ?
                """,
                (
                    session.ended_at,
                    session.observation_count,
                    session.contact_count,
                    session.event_count,
                    session.status,
                    session.session_id,
                )
            )
            conn.commit()

    def get_session(self, session_id: str) -> Optional[Session]:
        """Fetch session by ID."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
            row = cur.fetchone()
            if not row:
                return None
            return Session(
                session_id=row["session_id"],
                started_at=row["started_at"],
                ended_at=row["ended_at"],
                device_model=row["device_model"] or "Unknown",
                android_version=row["android_version"] or "Unknown",
                termux_version=row["termux_version"] or "Unknown",
                alpha_version=row["alpha_version"] or "1.0.0",
                is_mock=bool(row["is_mock"]),
                scenario=row["scenario"] or "production",
                observation_count=row["observation_count"],
                contact_count=row["contact_count"],
                event_count=row["event_count"],
                status=row["status"] or "COMPLETED"
            )

    def list_sessions(self, limit: int = 50) -> List[Session]:
        """List past monitoring sessions sorted descending by start time."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
            )
            sessions = []
            for row in cur.fetchall():
                sessions.append(
                    Session(
                        session_id=row["session_id"],
                        started_at=row["started_at"],
                        ended_at=row["ended_at"],
                        device_model=row["device_model"] or "Unknown",
                        android_version=row["android_version"] or "Unknown",
                        termux_version=row["termux_version"] or "Unknown",
                        alpha_version=row["alpha_version"] or "1.0.0",
                        is_mock=bool(row["is_mock"]),
                        scenario=row["scenario"] or "production",
                        observation_count=row["observation_count"],
                        contact_count=row["contact_count"],
                        event_count=row["event_count"],
                        status=row["status"] or "COMPLETED"
                    )
                )
            return sessions

    # --- Observation Operations ---

    def insert_observations(self, observations: List[Observation]) -> None:
        """Batch insert raw normalized observations using parameterized SQL."""
        if not observations:
            return
        records = [
            (
                obs.observation_id,
                obs.session_id,
                obs.timestamp,
                obs.source,
                obs.signal_type.value,
                obs.interface,
                obs.identifier,
                obs.mac_address,
                obs.ssid,
                obs.bssid,
                obs.device_name,
                obs.rssi,
                obs.frequency,
                obs.channel,
                obs.band,
                obs.security,
                obs.capabilities,
                obs.manufacturer,
                obs.oui,
                json.dumps(obs.raw_metadata),
                obs.scan_age_seconds,
                1 if obs.is_cached else 0,
                obs.provenance.value,
            )
            for obs in observations
        ]
        with self._get_connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO observations (
                    observation_id, session_id, timestamp, source, signal_type,
                    interface, identifier, mac_address, ssid, bssid, device_name,
                    rssi, frequency, channel, band, security, capabilities,
                    manufacturer, oui, raw_metadata, scan_age_seconds, is_cached,
                    provenance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records
            )
            conn.commit()

    def get_observations_for_session(self, session_id: str, limit: int = 1000) -> List[Observation]:
        """Fetch observations for a specific session."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM observations WHERE session_id = ? ORDER BY timestamp ASC LIMIT ?",
                (session_id, limit)
            )
            results = []
            for row in cur.fetchall():
                results.append(
                    Observation(
                        observation_id=row["observation_id"],
                        session_id=row["session_id"],
                        timestamp=row["timestamp"],
                        source=row["source"] or "",
                        signal_type=SignalType(row["signal_type"]),
                        interface=row["interface"] or "wlan0",
                        identifier=row["identifier"],
                        mac_address=row["mac_address"],
                        ssid=row["ssid"],
                        bssid=row["bssid"],
                        device_name=row["device_name"],
                        rssi=row["rssi"],
                        frequency=row["frequency"],
                        channel=row["channel"],
                        band=row["band"],
                        security=row["security"] or "UNKNOWN",
                        capabilities=row["capabilities"] or "",
                        manufacturer=row["manufacturer"] or "UNKNOWN",
                        oui=row["oui"] or "UNKNOWN",
                        raw_metadata=json.loads(row["raw_metadata"] or "{}"),
                        scan_age_seconds=row["scan_age_seconds"],
                        is_cached=bool(row["is_cached"]),
                        provenance=DataProvenance(row["provenance"]),
                    )
                )
            return results

    # --- Contact Operations ---

    def save_contacts(self, contacts: List[Contact]) -> None:
        """Batch upsert correlated contacts."""
        if not contacts:
            return
        records = [
            (
                c.contact_id,
                c.session_id,
                c.signal_type.value,
                c.identifier,
                c.mac_address,
                c.bssid,
                c.ssid,
                c.device_name,
                c.manufacturer,
                c.oui,
                1 if c.is_randomized_mac else 0,
                c.category.value,
                c.confidence,
                c.classification_reason,
                json.dumps(c.evidence),
                c.state.value,
                c.first_seen,
                c.last_seen,
                c.observation_count,
                c.last_rssi,
                c.min_rssi,
                c.max_rssi,
                c.mean_rssi,
                c.rssi_variance,
                c.rssi_trend,
                c.signal_category.value,
                c.channel,
                c.frequency,
                c.band,
                c.security,
                c.capabilities,
                1 if c.is_watchlist_match else 0,
                json.dumps(c.watchlist_tags),
            )
            for c in contacts
        ]
        with self._get_connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO contacts (
                    contact_id, session_id, signal_type, identifier, mac_address,
                    bssid, ssid, device_name, manufacturer, oui, is_randomized_mac,
                    category, confidence, classification_reason, evidence, state,
                    first_seen, last_seen, observation_count, last_rssi, min_rssi,
                    max_rssi, mean_rssi, rssi_variance, rssi_trend, signal_category,
                    channel, frequency, band, security, capabilities,
                    is_watchlist_match, watchlist_tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records
            )
            conn.commit()

    def get_contacts_for_session(
        self,
        session_id: str,
        state: Optional[str] = None,
        signal_type: Optional[str] = None
    ) -> List[Contact]:
        """Fetch contacts for session with optional state and signal_type filters."""
        query = "SELECT * FROM contacts WHERE session_id = ?"
        params: List[Any] = [session_id]
        
        if state:
            query += " AND state = ?"
            params.append(state.upper())
        if signal_type:
            query += " AND signal_type = ?"
            params.append(signal_type.upper())
            
        query += " ORDER BY last_seen DESC"
        
        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            contacts = []
            for row in cur.fetchall():
                contacts.append(
                    Contact(
                        contact_id=row["contact_id"],
                        session_id=row["session_id"],
                        signal_type=SignalType(row["signal_type"]),
                        identifier=row["identifier"],
                        mac_address=row["mac_address"],
                        bssid=row["bssid"],
                        ssid=row["ssid"],
                        device_name=row["device_name"],
                        manufacturer=row["manufacturer"] or "UNKNOWN",
                        oui=row["oui"] or "UNKNOWN",
                        is_randomized_mac=bool(row["is_randomized_mac"]),
                        category=DeviceCategory(row["category"]),
                        confidence=row["confidence"],
                        classification_reason=row["classification_reason"] or "",
                        evidence=json.loads(row["evidence"] or "[]"),
                        state=ContactState(row["state"]),
                        first_seen=row["first_seen"],
                        last_seen=row["last_seen"],
                        observation_count=row["observation_count"],
                        last_rssi=row["last_rssi"],
                        min_rssi=row["min_rssi"],
                        max_rssi=row["max_rssi"],
                        mean_rssi=row["mean_rssi"],
                        rssi_variance=row["rssi_variance"],
                        rssi_trend=row["rssi_trend"] or "STEADY",
                        signal_category=SignalCategory(row["signal_category"]),
                        channel=row["channel"],
                        frequency=row["frequency"],
                        band=row["band"],
                        security=row["security"] or "UNKNOWN",
                        capabilities=row["capabilities"] or "",
                        is_watchlist_match=bool(row["is_watchlist_match"]),
                        watchlist_tags=json.loads(row["watchlist_tags"] or "[]"),
                    )
                )
            return contacts

    # --- Event Operations ---

    def insert_events(self, events: List[Event]) -> None:
        """Batch insert events."""
        if not events:
            return
        records = [
            (
                ev.event_id,
                ev.session_id,
                ev.timestamp,
                ev.event_type,
                ev.severity.value,
                ev.related_identifier,
                ev.related_contact_id,
                ev.message,
                json.dumps(ev.evidence),
                json.dumps(ev.data),
            )
            for ev in events
        ]
        with self._get_connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO events (
                    event_id, session_id, timestamp, event_type, severity,
                    related_identifier, related_contact_id, message, evidence, data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records
            )
            conn.commit()

    def get_events_for_session(self, session_id: str, limit: int = 200) -> List[Event]:
        """Fetch recorded events for a session."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
                (session_id, limit)
            )
            events = []
            for row in cur.fetchall():
                events.append(
                    Event(
                        event_id=row["event_id"],
                        session_id=row["session_id"],
                        timestamp=row["timestamp"],
                        event_type=row["event_type"],
                        severity=EventSeverity(row["severity"]),
                        related_identifier=row["related_identifier"] or "",
                        related_contact_id=row["related_contact_id"],
                        message=row["message"],
                        evidence=json.loads(row["evidence"] or "[]"),
                        data=json.loads(row["data"] or "{}"),
                    )
                )
            return events

    # --- Retention & Pruning ---

    def prune_older_than(self, days: int = 30) -> Dict[str, int]:
        """Prune historical observations and events older than specified days."""
        cutoff = time.time() - (days * 86400)
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM observations WHERE timestamp < ?", (cutoff,))
            del_obs = cur.rowcount
            cur.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            del_events = cur.rowcount
            cur.execute("DELETE FROM sessions WHERE started_at < ? AND status != 'RUNNING'", (cutoff,))
            del_sessions = cur.rowcount
            conn.commit()
            return {
                "deleted_observations": del_obs,
                "deleted_events": del_events,
                "deleted_sessions": del_sessions,
            }
