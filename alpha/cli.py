"""
CLI Dispatcher and Entry Point for Alpha.

Provides commands:
- alpha (interactive monitor)
- alpha scan
- alpha monitor
- alpha devices
- alpha radar
- alpha analytics
- alpha events
- alpha timeline
- alpha session [list|show|export]
- alpha baseline [start|status|compare]
- alpha watchlist [add|list|remove]
- alpha export [--csv|--json|--markdown|--debrief]
- alpha diagnostics
- alpha capabilities [--json]
- alpha config [show|get|set|reset]
- alpha --self-test
- alpha --mock [--scenario <name>]
"""

import argparse
import json
import os
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any

from alpha import __version__, __app_name__
from alpha.config import AlphaConfig
from alpha.logger import setup_logger, get_logger
from alpha.models import (
    Session,
    Observation,
    Contact,
    Event,
    SignalType,
    ContactState,
    FreshnessState,
)
from alpha.storage.database import AlphaDatabase
from alpha.acquisition.wifi import TermuxWifiBackend
from alpha.acquisition.ble import TermuxBleBackend
from alpha.acquisition.mock import MockAcquisitionBackend
from alpha.correlation.tracker import ContactTracker
from alpha.signatures.rules import SignatureEngine
from alpha.classification.engine import HeuristicClassifier
from alpha.baseline.engine import BaselineEngine
from alpha.watchlist.engine import WatchlistEngine, WatchlistRule
from alpha.alerts.manager import AlertManager
from alpha.analytics.engine import AnalyticsEngine
from alpha.radar.radar import TerminalRadar
from alpha.export.exporter import AlphaExporter
from alpha.diagnostics import EnvironmentInspector
from alpha.self_test import run_self_test
from alpha.sanitizer import sanitize_string, sanitize_mac

# Configure terminal raw input helper cross-platform
_orig_termios = None

def _enable_cbreak_mode():
    """Enable non-blocking single-keypress terminal mode on POSIX/Termux."""
    global _orig_termios
    if sys.platform != "win32" and sys.stdin.isatty():
        try:
            import tty
            import termios
            _orig_termios = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            pass

def _restore_terminal_mode():
    """Restore standard terminal mode on exit."""
    global _orig_termios
    if sys.platform != "win32" and _orig_termios is not None and sys.stdin.isatty():
        try:
            import termios
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, _orig_termios)
        except Exception:
            pass
    # Show cursor again and reset color
    sys.stdout.write("\033[?25h\033[0m\n")
    sys.stdout.flush()

def _check_keypress() -> Optional[str]:
    """Non-blocking check for keypress."""
    if sys.platform == "win32":
        try:
            import msvcrt
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                try:
                    return ch.decode("utf-8", errors="ignore")
                except Exception:
                    return None
        except Exception:
            pass
    else:
        try:
            import select
            r, _, _ = select.select([sys.stdin], [], [], 0.0)
            if r:
                return sys.stdin.read(1)
        except Exception:
            pass
    return None


class AlphaApplication:
    """Main application controller orchestrating observation, storage, and UI."""

    def __init__(self, config: AlphaConfig, is_mock: bool = False, scenario: str = "normal"):
        self.config = config
        self.is_mock = is_mock
        self.scenario = scenario
        self.logger = setup_logger(config.log_file, config.log_level)
        self.db = AlphaDatabase(config.db_path)
        self.tracker = ContactTracker(
            new_window=config.new_window_seconds,
            active_window=config.active_window_seconds,
            stale_window=config.stale_window_seconds,
            jump_threshold=config.rssi_jump_threshold,
            rssi_strong=config.rssi_strong_threshold,
            rssi_medium=config.rssi_medium_threshold,
            rssi_weak=config.rssi_weak_threshold,
        )
        self.sig_engine = SignatureEngine(Path(config.config_dir) / "signatures.json")
        self.classifier = HeuristicClassifier(self.sig_engine)
        self.baseline_engine = BaselineEngine()
        self.watchlist_engine = WatchlistEngine(Path(config.config_dir) / "watchlist.json")
        self.alert_manager = AlertManager(
            enable_beep=config.terminal_beep,
            enable_vibrate=config.vibrate_on_watchlist,
            enable_notification=config.notification_on_watchlist,
            rate_limit_seconds=config.alert_rate_limit_seconds,
        )

        # Initialize backends
        if self.is_mock:
            self.wifi_backend = MockAcquisitionBackend(scenario=self.scenario)
            self.ble_backend = None
        else:
            self.wifi_backend = TermuxWifiBackend(command_timeout=config.scan_timeout_seconds)
            self.ble_backend = TermuxBleBackend()

        self.running = False
        self.current_session: Optional[Session] = None
        self.recent_events: List[Event] = []

    def start_session(self) -> Session:
        """Create and persist a new monitoring session."""
        plat = EnvironmentInspector.inspect_platform()
        sess = Session(
            started_at=time.time(),
            device_model=f"{plat['os']} {plat['arch']}",
            android_version=plat["android_release"],
            termux_version=plat["termux_version"],
            alpha_version=__version__,
            is_mock=self.is_mock,
            scenario=self.scenario if self.is_mock else "production",
            status="RUNNING"
        )
        self.db.create_session(sess)
        self.current_session = sess
        return sess

    def end_session(self) -> None:
        """Finalize and persist session completion."""
        if self.current_session:
            self.current_session.ended_at = time.time()
            self.current_session.status = "COMPLETED"
            self.current_session.contact_count = len(self.tracker.contacts)
            self.db.update_session(self.current_session)

    def run_single_scan(self) -> List[Observation]:
        """Perform one scan pass and update tracker and classification."""
        sess_id = self.current_session.session_id if self.current_session else "single_scan"
        batch = self.wifi_backend.scan(sess_id)
        
        all_obs = list(batch.observations)
        if self.ble_backend:
            ble_batch = self.ble_backend.scan(sess_id)
            all_obs.extend(ble_batch.observations)

        # Process observations through pipeline
        new_events = []
        for obs in all_obs:
            contact, evts = self.tracker.process_observation(obs, sess_id)
            self.classifier.classify(contact)
            wl_evts = self.watchlist_engine.evaluate(contact, sess_id)
            new_events.extend(evts)
            new_events.extend(wl_evts)

        # Check temporal stale transitions
        stale_evts = self.tracker.update_temporal_states(sess_id)
        new_events.extend(stale_evts)

        # Dispatch alerts
        for ev in new_events:
            self.alert_manager.dispatch(ev)

        # Persist to SQLite
        if self.current_session:
            self.db.insert_observations(all_obs)
            self.db.save_contacts(self.tracker.get_all_contacts())
            self.db.insert_events(new_events)
            self.current_session.observation_count += len(all_obs)
            self.current_session.event_count += len(new_events)
            self.current_session.contact_count = len(self.tracker.contacts)
            self.db.update_session(self.current_session)

        self.recent_events = new_events + self.recent_events
        self.recent_events = self.recent_events[:150]
        return all_obs

    def run_interactive_monitor(self) -> None:
        """Launch full interactive Terminal Dashboard monitoring loop."""
        from alpha.tui.engine import TerminalUI
        
        self.start_session()
        self.running = True
        ui = TerminalUI(self.current_session, self.config, ascii_only=self.config.ascii_only)

        # Register signal handlers for clean shutdown
        def handle_signal(sig, frame):
            self.running = False
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        # Setup terminal
        _enable_cbreak_mode()
        sys.stdout.write("\033[?25l\033[2J")  # Hide cursor, clear screen
        sys.stdout.flush()

        last_scan_time = 0.0
        last_meta = None

        try:
            while self.running:
                now = time.time()
                
                # Check for keyboard input
                key = _check_keypress()
                if key:
                    if key.lower() == "q":
                        self.running = False
                        break
                    elif key in ("1", "2", "3", "4", "5", "6"):
                        ui.active_tab = int(key)
                    elif key == "\t":
                        ui.active_tab = (ui.active_tab % 6) + 1
                    elif key.lower() == "p":
                        ui.is_paused = not ui.is_paused
                    elif key.lower() == "c":
                        # Cycle profile
                        profiles = ["BALANCED", "ACTIVE", "LOW_POWER"]
                        curr_idx = profiles.index(self.config.power_profile) if self.config.power_profile in profiles else 0
                        next_p = profiles[(curr_idx + 1) % len(profiles)]
                        self.config.apply_power_profile(next_p)
                    elif key.lower() == "r":
                        last_scan_time = 0.0  # Force scan

                # Perform scan pass if not paused and interval elapsed
                if not ui.is_paused and (now - last_scan_time) >= self.config.scan_interval_seconds:
                    sess_id = self.current_session.session_id
                    batch = self.wifi_backend.scan(sess_id)
                    last_meta = batch.metadata
                    
                    obs_list = list(batch.observations)
                    if self.ble_backend:
                        ble_batch = self.ble_backend.scan(sess_id)
                        obs_list.extend(ble_batch.observations)

                    new_evts = []
                    for obs in obs_list:
                        contact, evts = self.tracker.process_observation(obs, sess_id)
                        self.classifier.classify(contact)
                        wl_evts = self.watchlist_engine.evaluate(contact, sess_id)
                        new_evts.extend(evts)
                        new_evts.extend(wl_evts)

                    stale_evts = self.tracker.update_temporal_states(sess_id)
                    new_evts.extend(stale_evts)

                    for ev in new_evts:
                        self.alert_manager.dispatch(ev)

                    self.db.insert_observations(obs_list)
                    self.db.save_contacts(self.tracker.get_all_contacts())
                    self.db.insert_events(new_evts)

                    self.current_session.observation_count += len(obs_list)
                    self.current_session.event_count += len(new_evts)
                    self.current_session.contact_count = len(self.tracker.contacts)
                    self.db.update_session(self.current_session)

                    self.recent_events = new_evts + self.recent_events
                    self.recent_events = self.recent_events[:150]
                    last_scan_time = now

                # Render UI frame
                contacts = self.tracker.get_all_contacts()
                screen = ui.render_full_screen(
                    contacts=contacts,
                    events=self.recent_events,
                    last_metadata=last_meta
                )
                sys.stdout.write(screen)
                sys.stdout.flush()

                # Sleep brief interval according to ui refresh rate
                time.sleep(1.0 / max(1, self.config.ui_refresh_hz))

        finally:
            _restore_terminal_mode()
            self.end_session()
            print(f"\n[ALPHA] Session {self.current_session.session_id} completed successfully.")
            print(f"Total Observations: {self.current_session.observation_count} | Unique Contacts: {len(self.tracker.contacts)} | Events: {self.current_session.event_count}")


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser with all subcommands and shared flags."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--mock", action="store_true", help="Run in mock mode with simulated observations")
    common.add_argument("--scenario", default="normal", choices=["normal", "busy", "changing", "sparse", "unknown"], help="Mock scenario to execute")
    common.add_argument("--ascii", action="store_true", help="Force ASCII-only rendering without box drawing characters")
    common.add_argument("--profile", choices=["LOW_POWER", "BALANCED", "ACTIVE"], help="Set power profile")

    parser = argparse.ArgumentParser(
        prog="alpha",
        parents=[common],
        description="ALPHA: Termux-Native Rootless Wireless Observation & Environmental Awareness Platform"
    )
    parser.add_argument("-v", "--version", action="version", version=f"{__app_name__} v{__version__}")
    parser.add_argument("--self-test", action="store_true", help="Run automated internal subsystem self-test")

    subparsers = parser.add_subparsers(dest="subcommand", help="Alpha subcommands")

    # scan
    p_scan = subparsers.add_parser("scan", parents=[common], help="Perform single one-shot wireless scan")
    p_scan.add_argument("--json", action="store_true", help="Output raw JSON scan results")

    # monitor
    p_mon = subparsers.add_parser("monitor", parents=[common], help="Start continuous monitoring TUI dashboard")

    # devices
    p_dev = subparsers.add_parser("devices", parents=[common], help="List discovered wireless contacts from database")
    p_dev.add_argument("--session", help="Session ID to query (defaults to latest)")
    p_dev.add_argument("--active", action="store_true", help="Filter for ACTIVE contacts only")
    p_dev.add_argument("--wifi", action="store_true", help="Filter for Wi-Fi only")
    p_dev.add_argument("--ble", action="store_true", help="Filter for BLE only")

    # radar
    p_rad = subparsers.add_parser("radar", parents=[common], help="Display relative signal radar visualization")

    # analytics
    p_ana = subparsers.add_parser("analytics", parents=[common], help="Show RF spectrum, channel, and vendor analytics")
    p_ana.add_argument("--session", help="Session ID to analyze (defaults to latest)")

    # events
    p_evt = subparsers.add_parser("events", parents=[common], help="Show structured operational events")
    p_evt.add_argument("--limit", type=int, default=50, help="Number of events to list")

    # timeline
    p_time = subparsers.add_parser("timeline", parents=[common], help="Show temporal observation rate timeline")
    p_time.add_argument("--bucket", type=int, default=60, help="Timeline bucket size in seconds")

    # session
    p_sess = subparsers.add_parser("session", parents=[common], help="Session management commands")
    p_sess.add_argument("action", choices=["list", "show", "export"], help="Session action")
    p_sess.add_argument("session_id", nargs="?", help="Target session ID")

    # baseline
    p_base = subparsers.add_parser("baseline", parents=[common], help="Environmental baseline commands")
    p_base.add_argument("action", choices=["start", "status", "compare"], help="Baseline action")

    # watchlist
    p_wl = subparsers.add_parser("watchlist", parents=[common], help="Watchlist tracking commands")
    p_wl.add_argument("action", choices=["list", "add", "remove"], help="Watchlist action")
    p_wl.add_argument("--type", choices=["MAC", "OUI", "MANUFACTURER", "SSID", "DEVICE_NAME", "CATEGORY"], default="SSID")
    p_wl.add_argument("--pattern", help="Pattern or regex for rule")
    p_wl.add_argument("--label", help="Friendly label for watchlist target")
    p_wl.add_argument("--id", help="Rule ID to remove")

    # export
    p_exp = subparsers.add_parser("export", parents=[common], help="Export session data")
    p_exp.add_argument("--session", help="Session ID to export")
    p_exp.add_argument("--csv", action="store_true", help="Export contacts as CSV")
    p_exp.add_argument("--json", action="store_true", help="Export full session as JSON")
    p_exp.add_argument("--markdown", action="store_true", help="Export Markdown tables")
    p_exp.add_argument("--debrief", action="store_true", help="Export LLM-ready structured Debrief Report")
    p_exp.add_argument("-o", "--output", help="Output file destination (defaults to stdout)")

    # diagnostics
    subparsers.add_parser("diagnostics", parents=[common], help="Run comprehensive host and capability diagnostics")

    # capabilities
    p_cap = subparsers.add_parser("capabilities", parents=[common], help="Show capability matrix")
    p_cap.add_argument("--json", action="store_true", help="Output capability matrix as JSON")

    # config
    p_cfg = subparsers.add_parser("config", parents=[common], help="View or modify user configuration")
    p_cfg.add_argument("action", choices=["show", "get", "set", "reset"], help="Config action")
    p_cfg.add_argument("key", nargs="?", help="Configuration key")
    p_cfg.add_argument("value", nargs="?", help="Configuration value")

    return parser


def main() -> int:
    """Main CLI execution handler."""
    parser = build_parser()
    args = parser.parse_args()

    config = AlphaConfig.load()
    if args.ascii:
        config.ascii_only = True
    if args.profile:
        config.apply_power_profile(args.profile)

    # 1. Handle Self-Test
    if args.self_test:
        ok = run_self_test()
        return 0 if ok else 1

    # 2. Handle Diagnostics
    if args.subcommand == "diagnostics":
        print(EnvironmentInspector.format_diagnostics_report())
        return 0

    # 3. Handle Capabilities
    if args.subcommand == "capabilities":
        matrix = EnvironmentInspector.get_capability_matrix()
        if args.json:
            print(json.dumps(matrix.to_dict(), indent=2))
        else:
            print("ALPHA CAPABILITY MATRIX:")
            for k, v in matrix.to_dict().items():
                stat = "\033[92mYES\033[0m" if v else "\033[90mNO\033[0m"
                print(f"  {k:<32} : {stat}")
        return 0

    # 4. Handle Config
    if args.subcommand == "config":
        if args.action == "show":
            print(json.dumps(config.__dict__, indent=2))
        elif args.action == "get" and args.key:
            print(getattr(config, args.key, "Key not found"))
        elif args.action == "set" and args.key and args.value:
            if hasattr(config, args.key):
                orig_type = type(getattr(config, args.key))
                if orig_type == bool:
                    val = args.value.lower() in ("true", "1", "yes")
                elif orig_type == int:
                    val = int(args.value)
                elif orig_type == float:
                    val = float(args.value)
                else:
                    val = args.value
                setattr(config, args.key, val)
                config.save()
                print(f"Updated {args.key} = {val}")
        elif args.action == "reset":
            config = AlphaConfig()
            config.save()
            print("Configuration reset to defaults.")
        return 0

    # 5. Initialize Application
    app = AlphaApplication(config=config, is_mock=args.mock, scenario=args.scenario)

    # 6. Handle Subcommands
    if args.subcommand == "scan":
        app.start_session()
        obs = app.run_single_scan()
        app.end_session()
        if args.json:
            print(json.dumps([o.to_dict() for o in obs], indent=2))
        else:
            contacts = app.tracker.get_all_contacts()
            print(f"\n[ALPHA SCAN] Observed {len(obs)} item(s) -> {len(contacts)} unique contact(s):")
            print(f" {'ST':<3} {'TYPE':<4} {'SSID / NAME':<22} {'MAC ADDRESS':<18} {'VENDOR':<18} {'RSSI':<8} {'CH'}")
            print(" " + "-" * 78)
            for c in sorted(contacts, key=lambda x: x.last_rssi, reverse=True):
                name = sanitize_string(c.ssid or c.device_name or "[Hidden/None]", max_length=20)
                mfg = sanitize_string(c.manufacturer, max_length=16)
                print(f" {c.state.value[:2]:<3} {c.signal_type.value[:3]:<4} {name:<22} {c.mac_address:<18} {mfg:<18} {c.last_rssi:>4}dBm {str(c.channel or '-'):>3}")
        return 0

    elif args.subcommand == "devices":
        db = AlphaDatabase(config.db_path)
        sessions = db.list_sessions(1)
        sess_id = args.session or (sessions[0].session_id if sessions else None)
        if not sess_id:
            print("No recorded monitoring sessions found in database.")
            return 0
        state_filter = "ACTIVE" if args.active else None
        type_filter = "WIFI" if args.wifi else ("BLE" if args.ble else None)
        contacts = db.get_contacts_for_session(sess_id, state=state_filter, signal_type=type_filter)
        print(f"Contacts for session '{sess_id}' ({len(contacts)} found):")
        print(f" {'STATE':<7} {'TYPE':<5} {'SSID / NAME':<22} {'MAC ADDRESS':<18} {'VENDOR':<18} {'RSSI':<8} {'CH'}")
        print(" " + "-" * 82)
        for c in contacts:
            name = sanitize_string(c.ssid or c.device_name or "[Hidden/None]", max_length=20)
            mfg = sanitize_string(c.manufacturer, max_length=16)
            print(f" {c.state.value:<7} {c.signal_type.value:<5} {name:<22} {c.mac_address:<18} {mfg:<18} {c.last_rssi:>4}dBm {str(c.channel or '-'):>3}")
        return 0

    elif args.subcommand == "radar":
        app.start_session()
        app.run_single_scan()
        app.end_session()
        contacts = app.tracker.get_all_contacts()
        radar = TerminalRadar(ascii_only=config.ascii_only)
        print(radar.render(contacts, width=70, height=20, use_color=True))
        return 0

    elif args.subcommand == "analytics":
        db = AlphaDatabase(config.db_path)
        sessions = db.list_sessions(1)
        sess_id = args.session or (sessions[0].session_id if sessions else None)
        if not sess_id:
            # Run one scan to display analytics
            app.start_session()
            app.run_single_scan()
            contacts = app.tracker.get_all_contacts()
            app.end_session()
        else:
            contacts = db.get_contacts_for_session(sess_id)
        summary = AnalyticsEngine.compute_summary(contacts)
        print("\n=== ALPHA WIRELESS ANALYTICS ===")
        print(f"Total Unique Contacts: {summary['total_contacts']} (Wi-Fi: {summary['wifi_count']}, BLE: {summary['ble_count']})")
        print(f"Mean RSSI: {summary['mean_rssi']} dBm | Randomized MACs: {summary['randomized_mac_count']}")
        print("\nFrequency Bands:")
        for b, cnt in summary["band_distribution"].items():
            print(f"  {b:<12} : {cnt} AP(s)")
        print("\nTop Channels:")
        for ch, cnt in summary["channel_distribution"].items():
            print(f"  Channel {ch:<4} : {cnt} AP(s)")
        print("\nTop Manufacturers:")
        for mfg, cnt in list(summary["manufacturer_distribution"].items())[:8]:
            print(f"  {mfg:<26} : {cnt}")
        return 0

    elif args.subcommand == "events":
        db = AlphaDatabase(config.db_path)
        sessions = db.list_sessions(1)
        sess_id = sessions[0].session_id if sessions else "default"
        events = db.get_events_for_session(sess_id, limit=args.limit)
        print(f"Recorded Events ({len(events)}):")
        for ev in events:
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            print(f"[{ts}] [{ev.severity.value}] {ev.event_type:<18} ({ev.related_identifier}) : {ev.message}")
        return 0

    elif args.subcommand == "session":
        db = AlphaDatabase(config.db_path)
        if args.action == "list":
            sessions = db.list_sessions(50)
            print(f"Recorded Sessions ({len(sessions)}):")
            print(f" {'SESSION ID':<38} {'STARTED AT':<20} {'OBS':<6} {'CONTACTS':<9} {'STATUS'}")
            print(" " + "-" * 82)
            for s in sessions:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.started_at))
                print(f" {s.session_id:<38} {ts:<20} {s.observation_count:<6} {s.contact_count:<9} {s.status}")
        elif args.action == "show" and args.session_id:
            sess = db.get_session(args.session_id)
            if sess:
                print(json.dumps(sess.to_dict(), indent=2))
            else:
                print(f"Session '{args.session_id}' not found.")
        return 0

    elif args.subcommand == "watchlist":
        engine = app.watchlist_engine
        if args.action == "list":
            print(f"Configured Watchlist Rules ({len(engine.rules)}):")
            for r in engine.rules:
                print(f" - [{r.rule_id}] Type: {r.target_type:<12} Pattern: '{r.pattern}' Label: '{r.label}'")
        elif args.action == "add":
            if not args.pattern or not args.label:
                print("Error: --pattern and --label are required to add a watchlist rule.")
                return 1
            rule = WatchlistRule(
                rule_id=f"wl_{uuid.uuid4().hex[:6]}",
                target_type=args.type,
                pattern=args.pattern,
                label=args.label,
            )
            engine.add_rule(rule)
            print(f"Added watchlist rule: {rule.rule_id} ({rule.label})")
        elif args.action == "remove" and args.id:
            if engine.remove_rule(args.id):
                print(f"Removed watchlist rule: {args.id}")
            else:
                print(f"Rule ID '{args.id}' not found.")
        return 0

    elif args.subcommand == "timeline":
        db = AlphaDatabase(config.db_path)
        sessions = db.list_sessions(1)
        sess_id = sessions[0].session_id if sessions else None
        if not sess_id:
            print("No recorded monitoring observations found in database.")
            return 0
        obs = db.get_observations_for_session(sess_id)
        timeline = AnalyticsEngine.generate_timeline(obs, bucket_seconds=args.bucket)
        print(f"\n=== WIRELESS OBSERVATION TIMELINE (Session: {sess_id}) ===")
        print(f" {'TIME':<10} {'TOTAL OBS':<12} {'WI-FI':<8} {'BLE':<8} {'UNIQUE DEVICES'}")
        print(" " + "-" * 55)
        for t in timeline:
            print(f" {t['time_str']:<10} {t['total_observations']:<12} {t['wifi_count']:<8} {t['ble_count']:<8} {t['unique_devices']}")
        return 0

    elif args.subcommand == "baseline":
        db = AlphaDatabase(config.db_path)
        sessions = db.list_sessions(1)
        sess_id = sessions[0].session_id if sessions else None
        contacts = db.get_contacts_for_session(sess_id) if sess_id else []
        if args.action == "start":
            snap = app.baseline_engine.capture_snapshot(contacts, name="baseline_profile")
            print(f"[+] Environmental Baseline Captured ({snap.contact_count} contacts, {snap.wifi_count} Wi-Fi, {snap.ble_count} BLE)")
            print(f"    Mean RSSI: {snap.mean_rssi} dBm")
        elif args.action in ("status", "compare"):
            comp = app.baseline_engine.compare_with_current(contacts)
            print("\n=== ENVIRONMENTAL BASELINE COMPARISON ===")
            print(f"Status: {comp['status']}")
            if comp.get("deviations"):
                print("Observed Deviations:")
                for d in comp["deviations"]:
                    print(f" - {d}")
            else:
                print("No significant baseline deviations detected.")
        return 0

    elif args.subcommand == "export":
        db = AlphaDatabase(config.db_path)
        sessions = db.list_sessions(1)
        sess_id = args.session or (sessions[0].session_id if sessions else None)
        
        if not sess_id:
            # Run one scan to generate export data
            app.start_session()
            app.run_single_scan()
            app.end_session()
            sess = app.current_session
            contacts = app.tracker.get_all_contacts()
            events = app.recent_events
            obs = []
        else:
            sess = db.get_session(sess_id)
            contacts = db.get_contacts_for_session(sess_id)
            events = db.get_events_for_session(sess_id)
            obs = db.get_observations_for_session(sess_id)

        if args.csv:
            content = AlphaExporter.to_csv(contacts)
        elif args.json:
            content = AlphaExporter.to_json(sess, contacts, events, obs)
        elif args.markdown:
            content = AlphaExporter.to_markdown(sess, contacts, events)
        elif args.debrief or (not args.csv and not args.json and not args.markdown):
            content = AlphaExporter.to_debrief_report(sess, contacts, events, obs)

        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
            print(f"Export saved to: {args.output}")
        else:
            print(content)
        return 0

    # Default action: launch interactive TUI Monitor
    app.run_interactive_monitor()
    return 0


if __name__ == "__main__":
    sys.exit(main())
