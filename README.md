# Failed Login Detector

A Python + SQL based security tool that detects brute-force and credential-stuffing attacks by analyzing SSH authentication logs. Built as the foundation project for a series of SOC-relevant security tools.

## Overview

This tool simulates a basic SIEM (Security Information and Event Management) workflow:
it parses authentication logs, stores events in a structured database, detects suspicious
login patterns, and generates a security report with actionable recommendations.

## Features

- Parses raw SSH authentication logs using regex
- Stores all login attempts in a SQLite database
- Detects brute-force attacks (repeated failed logins from one IP)
- Detects credential-stuffing attempts (multiple usernames tried from one IP)
- Assigns severity levels (LOW / MEDIUM / HIGH / CRITICAL) based on attempt volume
- Generates a full text report with IP summaries and recommended firewall actions

## Architecture
auth.log → parser.py → SQLite DB → analyzer.py → reporter.py → report.txt
| Layer | File | Responsibility |
|---|---|---|
| Input | `data/auth.log` | Raw authentication log |
| Parsing | `src/parser.py` | Extracts timestamp, IP, username, status |
| Storage | `src/database.py` | All SQL operations (CRUD) |
| Analysis | `src/analyzer.py` | Threat detection logic |
| Output | `src/reporter.py` | Report generation |
| Config | `config.py` | Detection thresholds and file paths |

## Tech Stack

- Python 3
- SQLite3
- Regex (`re` module)

## Installation

```bash
git clone https://github.com/VonMagombo/failed-login-detector.git
cd failed-login-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py
```

The tool will parse `data/auth.log`, populate the database, run detection, and
generate `reports/report.txt`.

## Sample Output
[ALERT] HIGH - CREDENTIAL_STUFFING

IP: 192.168.1.105

Failed attempts: 6

Usernames tried: 5
## Detection Logic

- **Brute Force**: 5+ failed attempts from the same IP against the same username
- **Credential Stuffing**: 5+ failed attempts from the same IP across 3+ different usernames
- Severity scales with failed attempt count (configurable in `config.py`)

## Project Structure
failed-login-detector/

├── data/auth.log

├── database/security.db

├── reports/report.txt

├── src/

│   ├── parser.py

│   ├── database.py

│   ├── analyzer.py

│   └── reporter.py

├── main.py

├── config.py

└── README.md

## Future Improvements

- Real-time log monitoring instead of static file parsing
- Email/Slack alert notifications
- Web dashboard (Flask) for visualizing alerts
- GeoIP lookup for attacker IP addresses
- Integration with a real SIEM (Splunk/Wazuh)

## Author

**Matthew Vonroy Magombo**
BSc Computer Systems Engineering — Midlands State University
Google Cybersecurity Certified | ALX Cybersecurity Certified
[GitHub](https://github.com/VonMagombo) | [Portfolio](https://VonMagombo.github.io)

Commit Messages
For your first commit (initial working version):
Add failed login detector: SSH log parsing, SQLite storage, and brute-force detection

- Parse auth.log using regex to extract timestamp, IP, username, status
- Store login events in SQLite (logs, alerts, ip_summary tables)
- Detect brute-force and credential-stuffing patterns
- Generate severity-rated alerts and a full text report
For the bug fix you just made (table creation order):
Fix database initialization order in main.py

create_tables() must run before clear_all_tables(), since clearing
tables that don't exist yet on first run throws sqlite3.OperationalError
General format to follow going forward (good habit for your career):
<short summary, 50 chars or less, present tense>

<optional longer explanation — what changed and why, not how>
Examples for future commits:
Add config.py for centralized detection thresholds
Implement IP summary aggregation in database.py
Add README documentation
Fix regex pattern to handle multi-digit ports
Avoid messages like "fixed stuff" or "update" — recruiters and interviewers sometimes look at commit history, and clean messages signal good engineering discipline.failed-login-detector/

├── data/auth.log

├── database/security.db

├── reports/report.txt

├── src/

│   ├── parser.py

│   ├── database.py

│   ├── analyzer.py

│   └── reporter.py

├── main.py

├── config.py

└── README.md

## Future Improvements

- Real-time log monitoring instead of static file parsing
- Email/Slack alert notifications
- Web dashboard (Flask) for visualizing alerts
- GeoIP lookup for attacker IP addresses
- Integration with a real SIEM (Splunk/Wazuh)

## Author

**Matthew Vonroy Magombo**
BSc Computer Systems Engineering — Midlands State University
Google Cybersecurity Certified | ALX Cybersecurity Certified
[GitHub](https://github.com/VonMagombo) | [Portfolio](https://VonMagombo.github.io)

