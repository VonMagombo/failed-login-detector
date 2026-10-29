"""Runs the real pipeline (parse -> db -> analyze -> report) on a temp log + temp db."""
import os
import sqlite3

import config
import src.database as database
from src.analyzer import run_all_detections
from src.parser import parse_log_file
from src.reporter import generate_report
from tests.conftest import REFERENCE, make_line

ATTACK_LOG = "\n".join([
    # credential stuffing from 45.33.32.156, then it gets in
    *[make_line(f"Apr 25 10:30:0{i}", f"Failed password for invalid user {u} from 45.33.32.156 port 4000{i} ssh2")
      for i, u in enumerate(["support", "ubuntu", "git", "deploy-bot", "postgres"])],
    make_line("Apr 25 10:35:00", "Accepted password for git from 45.33.32.156 port 40100 ssh2"),
    # IPv6 brute force via rsyslog repeat compression (1 + 4 = 5 attempts)
    make_line("Apr 25 10:31:00", "Failed password for root from 2001:db8::bad port 50022 ssh2"),
    make_line("Apr 25 10:31:02", "message repeated 4 times: [ Failed password for root from 2001:db8::bad port 50022 ssh2]"),
    # harmless
    make_line("Apr 25 11:00:00", "Accepted publickey for alice from 10.0.0.5 port 60000 ssh2: ED25519 SHA256:abc"),
    make_line("Apr 25 11:00:01", "session opened for user alice", prog="systemd-logind"),
]) + "\n"


def run(db_dir, text):
    log = db_dir / "auth.log"
    log.write_text(text)
    result = parse_log_file(str(log), REFERENCE)
    run_all_detections()
    generate_report()
    return result


def test_full_pipeline(db):
    result = run(db, ATTACK_LOG)
    assert result == {"total": 10, "parsed": 9, "skipped": 1, "attempts": 12}

    alerts = {(a["ip_address"], a["alert_type"]) for a in database.get_all_alerts()}
    assert alerts == {
        ("45.33.32.156", "CREDENTIAL_STUFFING"),
        ("45.33.32.156", "POSSIBLE_COMPROMISE"),
        ("2001:db8::bad", "BRUTE_FORCE"),
    }

    # Most severe first
    assert database.get_all_alerts()[0]["severity"] == "CRITICAL"

    flagged = {r["ip_address"]: r["is_flagged"] for r in database.get_ip_summary()}
    assert flagged == {"45.33.32.156": 1, "2001:db8::bad": 1, "10.0.0.5": 0}

    summary = {r["ip_address"]: r for r in database.get_ip_summary()}
    assert summary["2001:db8::bad"]["failed_attempts"] == 5
    assert summary["45.33.32.156"]["success_attempts"] == 1
    assert summary["45.33.32.156"]["first_seen"] == "2026-04-25 10:30:00"

    report = open(config.REPORT_PATH).read()
    assert "ip6tables -A INPUT -s 2001:db8::bad -j DROP" in report
    assert "iptables -A INPUT -s 45.33.32.156 -j DROP" in report
    assert "10.0.0.5 -j DROP" not in report
    assert "URGENT" in report
    assert "<< FLAGGED" in report


def test_clean_log_has_no_alerts(db):
    run(db, make_line("Apr 25 11:00:00", "Accepted publickey for alice from 10.0.0.5 port 1 ssh2") + "\n")
    assert database.get_all_alerts() == []
    assert "No immediate action required." in open(config.REPORT_PATH).read()


def test_missing_log_returns_none(db):
    assert parse_log_file(str(db / "nope.log")) is None


def test_reset_replaces_old_schema(db):
    # A security.db left over from v1 has no auth_method column. Must not crash.
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.execute("DROP TABLE logs")
    conn.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, timestamp TEXT, ip_address TEXT, "
                 "username TEXT, status TEXT, raw_line TEXT)")
    conn.commit()
    conn.close()
    database.reset_database()
    run(db, ATTACK_LOG)
    assert len(database.get_all_alerts()) == 3


def test_sample_log_shipped_with_repo(db):
    # The demo log in data/ must keep showing every alert type
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "auth.log")
    parse_log_file(path, REFERENCE)
    run_all_detections()
    types = {a["alert_type"] for a in database.get_all_alerts()}
    assert types == {"BRUTE_FORCE", "CREDENTIAL_STUFFING", "POSSIBLE_COMPROMISE"}
    # alice's slow mistypes + key login must NOT be an alert
    assert "10.0.0.23" not in {a["ip_address"] for a in database.get_all_alerts()}
