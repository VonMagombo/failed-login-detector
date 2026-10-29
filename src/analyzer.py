# src/analyzer.py
from datetime import datetime, timedelta

import config
import src.database as database


TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def determine_severity(failed_count):
    """
    Determines alert severity based on number of failed attempts.
    Uses thresholds defined in config.py.
    """
    if failed_count >= config.SEVERITY_THRESHOLDS[config.SEVERITY_CRITICAL]:
        return config.SEVERITY_CRITICAL
    elif failed_count >= config.SEVERITY_THRESHOLDS[config.SEVERITY_HIGH]:
        return config.SEVERITY_HIGH
    elif failed_count >= config.SEVERITY_THRESHOLDS[config.SEVERITY_MEDIUM]:
        return config.SEVERITY_MEDIUM
    else:
        return config.SEVERITY_LOW


def find_peak_window(failures, window_minutes):
    """
    Sliding window: finds the busiest stretch of failures that fits inside
    window_minutes. Returns the list of failure rows in that stretch.

    Why a window: 5 failures in 10 seconds is an attack; 5 failures spread
    over a month is a user who forgets their password. Counting over the
    whole file can't tell them apart.

    Two pointers over time-sorted rows, O(n):
      - 'right' adds the next failure
      - 'left' drops failures that are now too old
    Input is sorted first (stable, so same-second rows keep file order).
    """
    failures = sorted(failures, key=lambda r: r['timestamp'])
    times = [datetime.strptime(r['timestamp'], TIME_FORMAT) for r in failures]
    window = timedelta(minutes=window_minutes)
    best_left, best_right = 0, 0   # best stretch is failures[best_left:best_right]
    left = 0
    for right in range(len(failures)):
        while times[right] - times[left] > window:
            left += 1
        if right + 1 - left > best_right - best_left:
            best_left, best_right = left, right + 1
    return failures[best_left:best_right]


def unique_in_order(values):
    """['root', 'admin', 'root'] -> ['root', 'admin'] (first-seen order)."""
    return list(dict.fromkeys(values))


def detect_brute_force(timelines):
    """
    Detects brute force and credential stuffing.

    Rule: an IP has at least FAILED_LOGIN_THRESHOLD failures inside any
    TIME_WINDOW_MINUTES window.
      - CREDENTIAL_STUFFING: that burst used UNIQUE_USERNAMES_THRESHOLD+
        different usernames (attacker working through a list of accounts)
      - BRUTE_FORCE: fewer usernames (hammering one account's password)
    """
    print("\n[ANALYZER] Running brute force detection...")
    alerts = []

    for ip, rows in timelines.items():
        failures = sorted((r for r in rows if r['status'] == 'FAILED'),
                          key=lambda r: r['timestamp'])
        if len(failures) < config.FAILED_LOGIN_THRESHOLD:
            continue

        burst = find_peak_window(failures, config.TIME_WINDOW_MINUTES)
        if len(burst) < config.FAILED_LOGIN_THRESHOLD:
            continue

        usernames = unique_in_order(r['username'] for r in burst)
        if len(usernames) >= config.UNIQUE_USERNAMES_THRESHOLD:
            alert_type = "CREDENTIAL_STUFFING"
        else:
            alert_type = "BRUTE_FORCE"

        alerts.append({
            "ip_address":      ip,
            "alert_type":      alert_type,
            "severity":        determine_severity(len(burst)),
            "failed_count":    len(burst),
            "usernames_tried": usernames,
            "first_seen":      burst[0]['timestamp'],
            "last_seen":       burst[-1]['timestamp'],
            "details":         f"{len(burst)} failures within {config.TIME_WINDOW_MINUTES} min "
                               f"({len(failures)} failures in total)",
        })

    return alerts


def detect_compromise(timelines):
    """
    Detects the most important pattern in an SSH log: an IP that failed
    many times and then logged in successfully. That usually means the
    attacker guessed the password.

    Rule: a SUCCESS from an IP whose earlier failures contain an attack
    burst (FAILED_LOGIN_THRESHOLD+ failures inside TIME_WINDOW_MINUTES).
    The burst is what separates an attacker from a user who mistyped their
    password a few times over the afternoon. The success can come up to
    COMPROMISE_LOOKBACK_DAYS after the burst: a slow attack that lands days
    later counts, but a burst from last year doesn't condemn today's login
    (IPs get reassigned, NAT gateways are shared).
    One alert per IP, for the first such success.
    """
    print("\n[ANALYZER] Running compromise detection...")
    alerts = []

    for ip, rows in timelines.items():
        failures_so_far = []
        lookback = timedelta(days=config.COMPROMISE_LOOKBACK_DAYS)
        # stable sort: a failure and a success in the same second keep file order
        for row in sorted(rows, key=lambda r: r['timestamp']):
            if row['status'] == 'FAILED':
                failures_so_far.append(row)
                continue
            success_time = datetime.strptime(row['timestamp'], TIME_FORMAT)
            recent = [f for f in failures_so_far
                      if success_time - datetime.strptime(f['timestamp'], TIME_FORMAT) <= lookback]
            burst = find_peak_window(recent, config.TIME_WINDOW_MINUTES)
            if len(burst) >= config.FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "ip_address":      ip,
                    "alert_type":      "POSSIBLE_COMPROMISE",
                    "severity":        config.SEVERITY_CRITICAL,
                    "failed_count":    len(recent),
                    "usernames_tried": unique_in_order(r['username'] for r in recent),
                    "first_seen":      recent[0]['timestamp'],
                    "last_seen":       row['timestamp'],
                    "details":         f"Accepted {row['auth_method']} for '{row['username']}' "
                                       f"at {row['timestamp']} after "
                                       f"{len(recent)} failed attempts",
                })
                break

    return alerts


def run_all_detections():
    """Runs all detection methods, saves alerts, flags IPs. Add more here as you build them."""
    print("\n[ANALYZER] Starting threat analysis...")
    timelines = database.get_logs_by_ip()

    alerts = detect_brute_force(timelines) + detect_compromise(timelines)

    for alert in alerts:
        database.insert_alert(
            ip_address      = alert['ip_address'],
            alert_type      = alert['alert_type'],
            severity        = alert['severity'],
            failed_count    = alert['failed_count'],
            usernames_tried = ', '.join(alert['usernames_tried']),
            first_seen      = alert['first_seen'],
            last_seen       = alert['last_seen'],
            details         = alert['details'],
        )
        database.flag_ip(alert['ip_address'])

        print(f"  [ALERT] {alert['severity']} - {alert['alert_type']}")
        print(f"          IP: {alert['ip_address']}")
        print(f"          Failed attempts: {alert['failed_count']}")
        print(f"          Usernames tried: {len(alert['usernames_tried'])}")

    print(f"[ANALYZER] Total alerts: {len(alerts)}")
    return len(alerts)
