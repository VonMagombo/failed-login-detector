# src/parser.py
import re
import ipaddress
from datetime import datetime, timedelta

import config
import src.database as database


# --- Line structure -----------------------------------------------------------
# An sshd line in auth.log has three parts:
#
#   <timestamp> <host> sshd[<pid>]: <message>
#
# The timestamp comes in two formats depending on the distro / rsyslog config:
#   classic syslog : "Apr 25 10:23:01"   (no year!)
#   RFC 3339 / ISO : "2026-04-25T10:23:01.123456+00:00"  (Ubuntu 24.04+ default)
#
# OpenSSH 9.8+ logs auth events from "sshd-session" instead of "sshd".
# We only accept lines TAGGED sshd / sshd-session, so "Failed password" text
# inside another program's message (sudo, cron, a web app) is ignored.
# LIMITATION: the syslog tag is not authenticated. Any local user can run
#   logger -p auth.info -t 'sshd[1]' "Failed password for root from 6.6.6.6 port 22 ssh2"
# and produce a line identical to a real one. Only journald metadata
# (_COMM / _UID) can tell them apart; see README "Known limitations".
LINE_PATTERN = re.compile(
    r'^(?:(?P<syslog_ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    r'|(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))'
    r'\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+(?P<message>.*)$'
)

# rsyslog collapses identical consecutive lines into:
#   message repeated 3 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]
# That one line stands for 3 more attempts, so we must count it 3 times.
REPEATED_PATTERN = re.compile(r'^message repeated (?P<count>\d+) times: \[\s*(?P<inner>.*?)\s*\]\s*$')

# "+02:00", "-0500" or "Z" at the end of an ISO timestamp
ISO_OFFSET = re.compile(r'(?P<sign>[+-])(?P<hh>\d{2}):?(?P<mm>\d{2})$')

# The auth event itself. Examples:
#   Failed password for root from 1.2.3.4 port 22 ssh2
#   Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
#   Accepted publickey for deploy from 2001:db8::1 port 51234 ssh2: ED25519 SHA256:...
#
# The username is matched GREEDILY on purpose. An attacker controls the
# username, so they can send "x from 6.6.6.6 port 22" as a username to try
# to frame another IP. sshd always appends the real "from <ip> port <n>" last,
# so taking the LAST occurrence is the one that can be trusted.
EVENT_PATTERN = re.compile(
    r'^(?P<result>Failed|Accepted)\s+'
    r'(?P<method>password|publickey|keyboard-interactive/pam|keyboard-interactive|hostbased)\s+'
    r'for\s+(?P<invalid>invalid user\s+)?(?P<username>.*)\s+'
    r'from\s+(?P<source>\S+)\s+port\s+(?P<port>\d+)'
    r'(?:\s+ssh\d)?(?::.*)?\s*$'
)


def parse_timestamp(syslog_ts=None, iso_ts=None, reference=None):
    """
    Converts either timestamp format to "YYYY-MM-DD HH:MM:SS".

    Storing ISO format matters: it sorts correctly as text, so SQL
    MIN/MAX/ORDER BY work. "Apr 9" vs "Apr 25" as raw text does not.

    Classic syslog has no year, so we assume the reference year (now), and
    if that lands in the future we use the previous year. That handles a log
    spanning Dec -> Jan read in January.
    """
    if iso_ts:
        # Parse the first 19 characters ourselves instead of fromisoformat(),
        # which in older Pythons rejects "Z", "+0200" and ".123".
        dt = datetime.strptime(iso_ts[:19], "%Y-%m-%dT%H:%M:%S")
        # If an offset is given, convert to UTC. Otherwise the repeated hour
        # when daylight saving ends, or hosts in different zones, would sort
        # events out of order and break the time window.
        offset = ISO_OFFSET.search(iso_ts)
        if offset:
            sign = -1 if offset.group("sign") == "-" else 1
            dt -= sign * timedelta(hours=int(offset.group("hh")), minutes=int(offset.group("mm")))
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    reference = reference or datetime.now()
    month_day_time = " ".join(syslog_ts.split())        # collapse "Apr  5" padding
    # Try this year, then last year. Last year is right when the date would be
    # in the future (a December log read in January), or doesn't exist this
    # year at all ("Feb 29" read in a non-leap year).
    for year in (reference.year, reference.year - 1):
        try:
            dt = datetime.strptime(f"{year} {month_day_time}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        if dt <= reference + timedelta(days=1):
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    raise ValueError(f"no valid year for {syslog_ts!r}")   # e.g. "Feb 30"


def parse_log_line(line, reference=None):
    """
    Uses Regular Expressions (regex) to extract data from a log line.

    A log line looks like:
    Apr 25 10:23:01 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2

    Returns a dict, or None if the line is not an sshd login attempt:
    - timestamp:   "2026-04-25 10:23:01"
    - ip_address:  "192.168.1.105"  (IPv4 or IPv6)
    - username:    "root"
    - status:      "FAILED" or "SUCCESS"
    - auth_method: "password", "publickey", ...
    - invalid_user: True if the account does not exist on the server
    - port:        source port as int
    - count:       how many attempts this line represents (rsyslog repeats)
    """
    line = line.lstrip("\ufeff").rstrip()   # BOM at file start, CRLF / trailing spaces at end
    match = LINE_PATTERN.match(line)
    if not match:
        return None

    message = match.group("message")
    count = 1
    repeated = REPEATED_PATTERN.match(message)
    if repeated:
        count = int(repeated.group("count"))
        message = repeated.group("inner")

    event = EVENT_PATTERN.match(message)
    if not event:
        return None

    try:
        timestamp = parse_timestamp(match.group("syslog_ts"), match.group("iso_ts"), reference)
    except ValueError:
        return None  # e.g. "Feb 30": not a real date, don't guess

    return {
        "timestamp":    timestamp,
        "ip_address":   normalize_source(event.group("source")),
        "username":     event.group("username"),
        "status":       "FAILED" if event.group("result") == "Failed" else "SUCCESS",
        "auth_method":  event.group("method"),
        "invalid_user": event.group("invalid") is not None,
        "port":         int(event.group("port")),
        "count":        count,
        "raw_line":     line.strip(),
    }


def normalize_source(source):
    """
    Returns the canonical form of an IP ("2001:DB8::0001" -> "2001:db8::1"),
    so the same attacker is never counted as two IPs.
    On dual-stack servers sshd logs IPv4 clients as "::ffff:1.2.3.4";
    that is the same host as "1.2.3.4", so unwrap it.
    A link-local scope ("fe80::1%eth0") is dropped: it names our interface,
    not the attacker, and ip6tables rejects it.
    If sshd has UseDNS on, the source is a hostname; DNS is case-insensitive,
    so lowercase it.
    """
    try:
        ip = ipaddress.ip_address(source.split("%", 1)[0])
    except ValueError:
        return source.lower()
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def parse_log_file(log_path=None, reference=None):
    """
    Reads the entire log file line by line.
    Parses each line and stores results in the database.
    Returns total counts for reporting.
    """
    log_path = log_path or config.LOG_FILE_PATH
    print(f"\n[PARSER] Reading log file: {log_path}")

    total_lines   = 0
    parsed_lines  = 0
    skipped_lines = 0
    events        = []

    try:
        # errors="replace": a single bad byte in a 1 GB log shouldn't crash the run
        with open(log_path, 'r', encoding='utf-8-sig', errors='replace') as file:
            for line in file:
                total_lines += 1
                result = parse_log_line(line, reference)
                if result:
                    events.append(result)
                    parsed_lines += 1
                else:
                    skipped_lines += 1
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_path}")
        return None

    # One connection and one transaction for the whole file instead of one per line
    attempts = database.insert_logs(events)
    database.rebuild_ip_summary()

    print(f"[PARSER] Total lines:   {total_lines}")
    print(f"[PARSER] Parsed:        {parsed_lines}")
    print(f"[PARSER] Skipped:       {skipped_lines}")
    print(f"[PARSER] Attempts:      {attempts}")

    return {
        "total":    total_lines,
        "parsed":   parsed_lines,
        "skipped":  skipped_lines,
        "attempts": attempts,
    }
