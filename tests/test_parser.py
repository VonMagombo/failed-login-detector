from datetime import datetime

import pytest

from src.parser import parse_log_line, parse_timestamp
from tests.conftest import REFERENCE, make_line


def parse(message, time="Apr 25 10:23:01", **kw):
    return parse_log_line(make_line(time, message, **kw), REFERENCE)


# --- The formats the old regex got wrong -------------------------------------

def test_original_format_still_parses():
    e = parse("Failed password for root from 192.168.1.105 port 22 ssh2")
    assert e["timestamp"] == "2026-04-25 10:23:01"
    assert (e["ip_address"], e["username"], e["status"]) == ("192.168.1.105", "root", "FAILED")
    assert e["auth_method"] == "password"
    assert e["invalid_user"] is False
    assert e["port"] == 22
    assert e["count"] == 1


def test_invalid_user_line_is_parsed():
    # The most common real brute-force line. The old regex returned None.
    e = parse("Failed password for invalid user admin from 1.2.3.4 port 40122 ssh2")
    assert e["username"] == "admin"
    assert e["invalid_user"] is True
    assert e["ip_address"] == "1.2.3.4"


@pytest.mark.parametrize("ip, canonical", [
    ("2001:db8::1", "2001:db8::1"),
    ("2001:DB8:0:0:0:0:0:0001", "2001:db8::1"),   # same host, different spelling
    ("::ffff:1.2.3.4", "1.2.3.4"),             # dual-stack: same host as plain IPv4
])
def test_ipv6_kept_whole_and_canonical(ip, canonical):
    # The old regex stored "2001:db8::1" as "2001"
    e = parse(f"Failed password for root from {ip} port 22 ssh2")
    assert e["ip_address"] == canonical


@pytest.mark.parametrize("user", ["deploy-bot", "john.smith", "svc_backup", "user@corp", "0day"])
def test_usernames_with_punctuation(user):
    e = parse(f"Failed password for invalid user {user} from 1.2.3.4 port 22 ssh2")
    assert e["username"] == user


def test_empty_username():
    # sshd logs this when the client sends an empty username
    e = parse("Failed password for invalid user  from 1.2.3.4 port 22 ssh2")
    assert e is not None
    assert e["username"] == ""


def test_accepted_publickey_with_key_suffix():
    e = parse("Accepted publickey for deploy from 10.0.0.5 port 51234 ssh2: "
              "ED25519 SHA256:3fQ1kVb0Xh2rT9yJ8uLmN4pZcWdEoGaHsIjKl5MnOpQ")
    assert (e["status"], e["auth_method"], e["username"]) == ("SUCCESS", "publickey", "deploy")


def test_keyboard_interactive():
    e = parse("Failed keyboard-interactive/pam for root from 1.2.3.4 port 22 ssh2")
    assert (e["status"], e["auth_method"]) == ("FAILED", "keyboard-interactive/pam")


def test_message_repeated_counts_every_attempt():
    e = parse("message repeated 4 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]")
    assert e["count"] == 4
    assert e["username"] == "root"


def test_openssh_98_sshd_session_process():
    e = parse("Failed password for root from 1.2.3.4 port 22 ssh2", prog="sshd-session")
    assert e is not None


def test_iso_timestamp_converted_to_utc():
    line = ("2026-04-25T10:23:01.123456+02:00 server sshd[99]: "
            "Failed password for root from 1.2.3.4 port 22 ssh2")
    assert parse_log_line(line, REFERENCE)["timestamp"] == "2026-04-25 08:23:01"


def test_iso_same_instant_different_zones_match():
    # Critic #3: these are the same moment and must sort as such
    a = parse_timestamp(iso_ts="2026-04-25T10:00:00+00:00")
    b = parse_timestamp(iso_ts="2026-04-25T12:00:00+02:00")
    c = parse_timestamp(iso_ts="2026-04-25T05:00:00-0500")
    assert a == b == c == "2026-04-25 10:00:00"


def test_iso_offset_crosses_midnight():
    assert parse_timestamp(iso_ts="2026-01-01T01:00:00+03:00") == "2025-12-31 22:00:00"


def test_iso_timestamp_z_suffix():
    line = "2026-04-25T10:23:01Z server sshd[99]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert parse_log_line(line, REFERENCE)["timestamp"] == "2026-04-25 10:23:01"


# --- Security: attacker-controlled usernames ---------------------------------

def test_username_cannot_spoof_source_ip():
    # Attacker at 1.2.3.4 sends a username crafted to look like another IP.
    # We must blame 1.2.3.4, not 6.6.6.6.
    e = parse("Failed password for invalid user x from 6.6.6.6 port 22 ssh2 "
              "from 1.2.3.4 port 5555 ssh2")
    assert e["ip_address"] == "1.2.3.4"
    assert e["port"] == 5555
    assert e["username"] == "x from 6.6.6.6 port 22 ssh2"


def test_other_programs_cannot_inject_ssh_events():
    # Same text, but logged by something that is not sshd
    assert parse("Failed password for root from 6.6.6.6 port 22 ssh2", prog="webapp") is None
    assert parse("Failed password for root from 6.6.6.6 port 22 ssh2", prog="fakesshd") is None


# --- Lines that must be skipped ----------------------------------------------

@pytest.mark.parametrize("line", [
    "",
    "   ",
    "garbage",
    make_line("Apr 25 10:00:00", "Invalid user support from 1.2.3.4 port 40122"),
    make_line("Apr 25 10:00:00", "Connection closed by authenticating user root 1.2.3.4 port 22 [preauth]"),
    make_line("Apr 25 10:00:00", "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)"),
    make_line("Apr 25 10:00:00", "alice : TTY=pts/0 ; COMMAND=/usr/bin/apt", prog="sudo"),
    make_line("Feb 30 10:00:00", "Failed password for root from 1.2.3.4 port 22 ssh2"),  # no Feb 30
])
def test_non_auth_lines_are_skipped(line):
    assert parse_log_line(line, REFERENCE) is None


# --- Timestamps --------------------------------------------------------------

def test_single_digit_day_padding():
    # syslog pads single-digit days with a space: "Apr  5"
    assert parse("Failed password for root from 1.2.3.4 port 22 ssh2",
                 time="Apr  5 09:00:00")["timestamp"] == "2026-04-05 09:00:00"


def test_iso_timestamps_sort_correctly_as_text():
    # The bug being fixed: as raw text, "Apr 9" > "Apr 25"
    assert parse_timestamp("Apr  9 10:00:00", reference=REFERENCE) < \
           parse_timestamp("Apr 25 10:00:00", reference=REFERENCE)


def test_year_rollover_december_log_read_in_january():
    january = datetime(2027, 1, 2, 8, 0, 0)
    assert parse_timestamp("Dec 31 23:59:59", reference=january) == "2026-12-31 23:59:59"
    assert parse_timestamp("Jan  1 00:00:01", reference=january) == "2027-01-01 00:00:01"


def test_leap_day_in_leap_year():
    assert parse_timestamp("Feb 29 12:00:00", reference=datetime(2028, 3, 1)) == "2028-02-29 12:00:00"


@pytest.mark.parametrize("ts, utc", [
    ("2026-04-25T10:23:01+0200",      "2026-04-25 08:23:01"),   # offset without colon
    ("2026-04-25T10:23:01.123-05:00", "2026-04-25 15:23:01"),   # 3-digit fraction
    ("2026-04-25T10:23:01Z",          "2026-04-25 10:23:01"),
    ("2026-04-25T10:23:01",           "2026-04-25 10:23:01"),   # no offset: kept as written
])
def test_iso_timestamp_variants(ts, utc):
    line = f"{ts} server sshd[99]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert parse_log_line(line, REFERENCE)["timestamp"] == utc


def test_feb_29_in_non_leap_reference_year_uses_previous_leap_year():
    # Critic #4: read in Jan 2029, "Feb 29" can only be 2028
    assert parse_timestamp("Feb 29 10:00:00", reference=datetime(2029, 1, 5)) == "2028-02-29 10:00:00"


# --- Critic findings: line endings, encodings, source normalization ----------

@pytest.mark.parametrize("ending", ["\r\n", " \n", "\t\n"])
def test_repeated_line_with_crlf_or_trailing_space(ending):
    # Critic #2: CRLF made "message repeated" lines vanish silently
    line = make_line("Apr 25 10:23:01",
                     "message repeated 3 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]") + ending
    e = parse_log_line(line, REFERENCE)
    assert e is not None and e["count"] == 3


def test_byte_order_mark_on_first_line():
    # Critic #9
    line = "\ufeff" + make_line("Apr 25 10:23:01", "Failed password for root from 1.2.3.4 port 22 ssh2")
    assert parse_log_line(line, REFERENCE) is not None


def test_byte_order_mark_in_file(db):
    from src.parser import parse_log_file
    log = db / "bom.log"
    log.write_bytes(b"\xef\xbb\xbf" +
                    make_line("Apr 25 10:23:01", "Failed password for root from 1.2.3.4 port 22 ssh2").encode())
    assert parse_log_file(str(log), REFERENCE)["parsed"] == 1


def test_ipv6_scope_is_dropped():
    # Critic #6: "%eth0" would end up in the ip6tables command
    e = parse("Accepted password for root from fe80::1%eth0 port 22 ssh2")
    assert e["ip_address"] == "fe80::1"


def test_hostnames_are_lowercased():
    # Critic #7: UseDNS hostnames are case-insensitive
    a = parse("Failed password for root from Evil.Example.COM port 22 ssh2")
    b = parse("Failed password for root from evil.example.com port 22 ssh2")
    assert a["ip_address"] == b["ip_address"] == "evil.example.com"


def test_forged_syslog_tag_is_accepted_known_limitation():
    # Critic #1: `logger -t 'sshd[999]' ...` is indistinguishable from sshd in a
    # flat text log. This pins the documented limitation so nobody claims otherwise.
    assert parse("Failed password for root from 6.6.6.6 port 22 ssh2", pid=999) is not None
