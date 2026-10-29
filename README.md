# Failed Login Detector

![tests](https://github.com/VonMagombo/failed-login-detector/actions/workflows/tests.yml/badge.svg)

A Python + SQL based security tool that detects brute-force attacks, credential stuffing,
and likely account compromises by analyzing SSH authentication logs. Built as the
foundation project for a series of SOC-relevant security tools.

## Overview

This tool simulates a basic SIEM (Security Information and Event Management) workflow:
it parses authentication logs, stores events in a structured database, detects suspicious
login patterns, and generates a security report with actionable recommendations.

## Features

- Parses real-world OpenSSH log lines, including:
  - `Failed password for invalid user ...` (the most common brute-force line)
  - IPv4 and IPv6 sources (dual-stack `::ffff:1.2.3.4` is treated as `1.2.3.4`)
  - password, publickey and keyboard-interactive logins
  - rsyslog's `message repeated N times: [ ... ]`, counted as N attempts
  - classic syslog (`Apr 25 10:23:01`) and ISO 8601 (`2026-04-25T10:23:01+00:00`) timestamps
  - OpenSSH 9.8+ `sshd-session` process name
- Resists username injection: a username crafted to contain `from <other-ip>` cannot frame
  another IP, and "Failed password" text inside other programs' messages (sudo, cron, ...) is ignored.
  Lines that forge the `sshd` tag itself are a known limitation, see below.
- Handles CRLF line endings, a UTF-8 byte-order mark, IPv6 scope ids (`fe80::1%eth0`) and
  mixed-case hostnames (sshd `UseDNS`)
- Stores all login attempts in a SQLite database
- Detects brute-force and credential-stuffing bursts inside a sliding time window
- Detects **possible compromise**: a successful login from an IP that was attacking
- Assigns severity levels (MEDIUM / HIGH / CRITICAL)
- Generates a text report with IP summaries and firewall commands (`iptables` / `ip6tables`)

## Architecture

```
auth.log → parser.py → SQLite DB → analyzer.py → reporter.py → report.txt
```

| Layer | File | Responsibility |
|---|---|---|
| Input | `data/auth.log` | Raw authentication log (sample included) |
| Parsing | `src/parser.py` | Extracts timestamp, IP, username, status, auth method, port |
| Storage | `src/database.py` | All SQL operations |
| Analysis | `src/analyzer.py` | Threat detection logic |
| Output | `src/reporter.py` | Report generation |
| Config | `config.py` | Detection thresholds and file paths |

## Tech Stack

- Python 3.10+ (standard library only)
- SQLite3
- Regex (`re` module)
- pytest (tests only)

## Installation

```bash
git clone https://github.com/VonMagombo/failed-login-detector.git
cd failed-login-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt   # only needed to run the tests
```

## Usage

```bash
python3 main.py                        # analyze the sample log in data/auth.log
sudo python3 main.py /var/log/auth.log # analyze a real server log
```

The tool rebuilds `database/security.db` from scratch on every run and writes
`reports/report.txt`. Both are generated files and are not tracked in git.

## Running the tests

```bash
python3 -m pytest -v
```

The suite covers the parser (log formats, IPv6, injection attempts, timestamps),
the detection rules (window boundaries, false positives, severity) and the full
pipeline end to end on a temporary database. It runs on every push via GitHub Actions.

## Sample Output

```
  [***] CRITICAL ALERT
     Type       : POSSIBLE_COMPROMISE
     IP Address : 192.168.1.105
     Failures   : 6
     Usernames  : root, admin, matthew, test, user
     First seen : 2026-04-25 10:23:01
     Last seen  : 2026-04-25 10:26:30
     Details    : Accepted password for 'test' at 2026-04-25 10:26:30 after 6 failed attempts
```

## Detection Logic

All thresholds live in `config.py`.

- **Burst**: at least `FAILED_LOGIN_THRESHOLD` (5) failures from one IP inside any
  `TIME_WINDOW_MINUTES` (10) window. Five failures in ten seconds is an attack; five
  spread over a month is someone who forgets their password.
- **Credential Stuffing**: a burst that used `UNIQUE_USERNAMES_THRESHOLD` (3) or more
  different usernames (working through a list of accounts).
- **Brute Force**: a burst that used fewer usernames (hammering one account's password).
- **Possible Compromise** (always CRITICAL): a successful login from an IP that had a
  burst in the previous `COMPROMISE_LOOKBACK_DAYS` (7). A slow attack that lands days
  later is still caught, but a burst from last year doesn't condemn today's login from a
  reassigned IP or shared NAT.
- **Severity** for bursts scales with the number of failures in the busiest window:
  5+ MEDIUM, 10+ HIGH, 20+ CRITICAL. LOW (3+) only appears if you lower
  `FAILED_LOGIN_THRESHOLD` below 5 in `config.py`.

Timestamps are stored as `YYYY-MM-DD HH:MM:SS` so they sort correctly:

- ISO 8601 timestamps with an offset are converted to UTC, so the repeated hour at the end
  of daylight saving time, or hosts in different zones, can't reorder events.
- Syslog timestamps have no year and no zone. They stay in server local time, with the
  current year assumed, or the previous year if the date would be in the future (a December
  log read in January) or doesn't exist this year (`Feb 29`).

## Known limitations

- **Forged sshd lines.** The syslog tag isn't authenticated, so any local user can run
  `logger -p auth.info -t 'sshd[1]' "Failed password for root from 6.6.6.6 port 22 ssh2"`
  and write a line identical to a real one. Five of those would get the report to suggest
  blocking 6.6.6.6. A flat `auth.log` can't tell them apart; reading from journald and
  checking `_COMM=sshd` / `_UID=0` can. Review the suggested `iptables` commands before
  running them.
- **Pre-auth scans aren't counted.** Only actual authentication attempts are parsed.
  `Invalid user X from IP` and `Connection closed ... [preauth]` lines are skipped, so a
  server with `PasswordAuthentication no` shows scanners as zero alerts.
- **Don't mix the two timestamp formats in one file.** ISO lines are UTC and syslog lines are local time.

## Project Structure

```
failed-login-detector/
├── data/auth.log            sample log covering every alert type
├── database/                security.db is generated here
├── reports/                 report.txt is generated here
├── src/
│   ├── parser.py
│   ├── database.py
│   ├── analyzer.py
│   └── reporter.py
├── tests/
│   ├── test_parser.py
│   ├── test_analyzer.py
│   └── test_end_to_end.py
├── main.py
├── config.py
├── requirements-dev.txt
└── README.md
```

## Future Improvements

- Real-time log monitoring (`--follow`) instead of static file parsing
- JSON alert output for ingestion by a SIEM (Splunk/Wazuh)
- Email/Slack alert notifications
- Web dashboard (Flask) for visualizing alerts
- GeoIP lookup for attacker IP addresses

## Author

**Matthew Vonroy Magombo**
BSc Computer Systems Engineering — Midlands State University
Google Cybersecurity Certified | ALX Cybersecurity Certified
[GitHub](https://github.com/VonMagombo) | [Portfolio](https://VonMagombo.github.io)
