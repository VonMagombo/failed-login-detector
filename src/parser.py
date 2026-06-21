# src/parser.py
import re
import config
import src.database as database

def parse_log_line(line):
    """
    Uses Regular Expressions (regex) to extract data from a log line.
    
    A log line looks like:
    Apr 25 10:23:01 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
    
    We want to extract:
    - timestamp: "Apr 25 10:23:01"
    - status: "Failed" or "Accepted"
    - username: "root"
    - ip_address: "192.168.1.105"
    """

    # This is a regex pattern — it describes what a log line looks like
    # Each part in () is a "capture group" — data we want to extract
    pattern = r'(\w+\s+\d+\s+[\d:]+).*?(Failed|Accepted)\s+password\s+for\s+(\w+)\s+from\s+([\d.]+)'

    # re.search scans the line for the pattern
    match = re.search(pattern, line)

    if match:
        timestamp  = match.group(1)  # "Apr 25 10:23:01"
        status_raw = match.group(2)  # "Failed" or "Accepted"
        username   = match.group(3)  # "root"
        ip_address = match.group(4)  # "192.168.1.105"

        # Normalize status to uppercase
        status = "FAILED" if status_raw == "Failed" else "SUCCESS"

        return {
            "timestamp":  timestamp,
            "ip_address": ip_address,
            "username":   username,
            "status":     status,
            "raw_line":   line.strip()
        }

    return None  # line didn't match our pattern — skip it


def parse_log_file():
    """
    Reads the entire log file line by line.
    Parses each line and stores results in the database.
    Returns total counts for reporting.
    """
    print(f"\n[PARSER] Reading log file: {config.LOG_FILE_PATH}")

    total_lines   = 0
    parsed_lines  = 0
    skipped_lines = 0

    try:
        with open(config.LOG_FILE_PATH, 'r') as file:
            for line in file:
                total_lines += 1

                # Skip empty lines
                if not line.strip():
                    skipped_lines += 1
                    continue

                # Try to parse the line
                result = parse_log_line(line)

                if result:
                    # Store in database
                    database.insert_log(
                        timestamp  = result['timestamp'],
                        ip_address = result['ip_address'],
                        username   = result['username'],
                        status     = result['status'],
                        raw_line   = result['raw_line']
                    )
                    # Update IP summary
                    database.update_ip_summary(
                        ip_address = result['ip_address'],
                        status     = result['status'],
                        username   = result['username'],
                        timestamp  = result['timestamp']
                    )
                    parsed_lines += 1
                else:
                    skipped_lines += 1

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {config.LOG_FILE_PATH}")
        return None

    print(f"[PARSER] Total lines:   {total_lines}")
    print(f"[PARSER] Parsed:        {parsed_lines}")
    print(f"[PARSER] Skipped:       {skipped_lines}")

    return {
        "total":   total_lines,
        "parsed":  parsed_lines,
        "skipped": skipped_lines
    }