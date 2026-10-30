from datetime import datetime, timedelta

import pytest

import config
from src.analyzer import (detect_brute_force, detect_compromise, determine_severity,
                          find_peak_window)

START = datetime(2026, 4, 25, 10, 0, 0)


def ev(seconds, status="FAILED", user="root", ip="1.2.3.4", method="password"):
    """One timeline row, `seconds` after START (same keys the analyzer reads from the db)."""
    return {
        "timestamp":   (START + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address":  ip,
        "username":    user,
        "status":      status,
        "auth_method": method,
    }


def timeline(*rows):
    out = {}
    for r in rows:
        out.setdefault(r["ip_address"], []).append(r)
    return out


@pytest.fixture(autouse=True)
def default_thresholds(monkeypatch):
    # Pin the values these tests are written against, whatever config.py says
    monkeypatch.setattr(config, "FAILED_LOGIN_THRESHOLD", 5)
    monkeypatch.setattr(config, "TIME_WINDOW_MINUTES", 10)
    monkeypatch.setattr(config, "UNIQUE_USERNAMES_THRESHOLD", 3)
    monkeypatch.setattr(config, "COMPROMISE_LOOKBACK_DAYS", 7)


# --- Sliding window ----------------------------------------------------------

def test_peak_window_empty():
    assert find_peak_window([], 10) == []


def test_peak_window_picks_densest_stretch():
    rows = [ev(0), ev(3600), ev(3601), ev(3602), ev(7200)]
    assert [r["timestamp"][-8:] for r in find_peak_window(rows, 10)] == \
           ["11:00:00", "11:00:01", "11:00:02"]


def test_peak_window_boundary_is_inclusive():
    # Exactly 10:00 apart still fits a 10 minute window
    assert len(find_peak_window([ev(0), ev(600)], 10)) == 2
    assert len(find_peak_window([ev(0), ev(601)], 10)) == 1


# --- Brute force / credential stuffing ---------------------------------------

def test_brute_force_one_user_fast():
    alerts = detect_brute_force(timeline(*[ev(i * 2) for i in range(5)]))
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "BRUTE_FORCE"
    assert alerts[0]["failed_count"] == 5


def test_below_threshold_no_alert():
    assert detect_brute_force(timeline(*[ev(i) for i in range(4)])) == []


def test_slow_failures_outside_window_no_alert():
    # A user mistyping once every 20 minutes. The old whole-file count flagged this.
    assert detect_brute_force(timeline(*[ev(i * 1200, user="alice") for i in range(10)])) == []


def test_credential_stuffing_many_usernames():
    users = ["root", "admin", "oracle", "git", "test"]
    alerts = detect_brute_force(timeline(*[ev(i, user=u) for i, u in enumerate(users)]))
    assert alerts[0]["alert_type"] == "CREDENTIAL_STUFFING"
    assert alerts[0]["usernames_tried"] == users


def test_two_usernames_is_still_brute_force():
    alerts = detect_brute_force(timeline(*[ev(i, user=("root" if i % 2 else "admin")) for i in range(6)]))
    assert alerts[0]["alert_type"] == "BRUTE_FORCE"


def test_ips_are_counted_separately():
    rows = [ev(i, ip="1.1.1.1") for i in range(3)] + [ev(i, ip="2.2.2.2") for i in range(3)]
    assert detect_brute_force(timeline(*rows)) == []


def test_successes_do_not_count_as_failures():
    rows = [ev(i) for i in range(4)] + [ev(10, status="SUCCESS")]
    assert detect_brute_force(timeline(*rows)) == []


@pytest.mark.parametrize("count, severity", [
    (3, "LOW"), (5, "MEDIUM"), (9, "MEDIUM"), (10, "HIGH"), (19, "HIGH"), (20, "CRITICAL"),
])
def test_severity_thresholds(count, severity):
    assert determine_severity(count) == severity


def test_severity_uses_burst_not_total():
    # 5 fast failures then 50 slow ones: the attack burst is 5, so MEDIUM
    rows = [ev(i) for i in range(5)] + [ev(10_000 + i * 3600) for i in range(50)]
    alert = detect_brute_force(timeline(*rows))[0]
    assert alert["failed_count"] == 5
    assert alert["severity"] == "MEDIUM"


# --- Compromise --------------------------------------------------------------

def test_success_after_burst_is_compromise():
    rows = [ev(i) for i in range(6)] + [ev(30, status="SUCCESS", user="root")]
    alerts = detect_compromise(timeline(*rows))
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "POSSIBLE_COMPROMISE"
    assert alerts[0]["severity"] == "CRITICAL"
    assert "after 6 failed attempts" in alerts[0]["details"]


def test_success_days_after_burst_is_still_compromise():
    rows = [ev(i) for i in range(5)] + [ev(3 * 86400, status="SUCCESS")]
    assert len(detect_compromise(timeline(*rows))) == 1


def test_success_before_failures_is_not_compromise():
    rows = [ev(0, status="SUCCESS")] + [ev(10 + i) for i in range(10)]
    assert detect_compromise(timeline(*rows)) == []


def test_forgetful_user_is_not_compromise():
    # 5 mistypes spread over 80 minutes, then a login: not an attack
    rows = [ev(i * 1200, user="alice") for i in range(5)] + [ev(6000, status="SUCCESS", user="alice")]
    assert detect_compromise(timeline(*rows)) == []


def test_success_from_different_ip_is_not_compromise():
    rows = [ev(i, ip="1.1.1.1") for i in range(10)] + [ev(30, status="SUCCESS", ip="2.2.2.2")]
    assert detect_compromise(timeline(*rows)) == []


def test_one_compromise_alert_per_ip():
    rows = [ev(i) for i in range(5)] + [ev(30, status="SUCCESS"), ev(40, status="SUCCESS")]
    assert len(detect_compromise(timeline(*rows))) == 1


# --- Critic findings ---------------------------------------------------------

def test_peak_window_sorts_unsorted_input():
    # Critic #5: unsorted input produced first_seen > last_seen
    rows = [ev(0), ev(4 * 86400), ev(1), ev(2), ev(3), ev(4)]
    alert = detect_brute_force(timeline(*rows))[0]
    assert alert["failed_count"] == 5
    assert alert["first_seen"] <= alert["last_seen"]
    assert alert["last_seen"] == ev(4)["timestamp"]


def test_compromise_with_unsorted_timeline():
    rows = [ev(30, status="SUCCESS")] + [ev(i) for i in range(5)]
    assert len(detect_compromise(timeline(*rows))) == 1


def test_same_second_success_before_fifth_failure_keeps_file_order():
    rows = [ev(0), ev(0), ev(0), ev(0), ev(0, status="SUCCESS"), ev(0)]
    assert detect_compromise(timeline(*rows)) == []


def test_old_burst_does_not_condemn_much_later_login():
    # Critic #10: burst last year, legit login today (reassigned IP / shared NAT)
    rows = [ev(i) for i in range(10)] + [ev(400 * 86400, status="SUCCESS")]
    assert detect_compromise(timeline(*rows)) == []


def test_lookback_boundary():
    burst = [ev(i) for i in range(5)]
    # The whole burst must fall inside the lookback, so measure from its FIRST failure
    inside = burst + [ev(7 * 86400, status="SUCCESS")]       # first failure exactly 7 days old
    outside = burst + [ev(7 * 86400 + 1, status="SUCCESS")]  # first failure ages out: 4 left
    assert len(detect_compromise(timeline(*inside))) == 1
    assert detect_compromise(timeline(*outside)) == []
