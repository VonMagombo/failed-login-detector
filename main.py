# main.py
# This is the file you run. It orchestrates everything.

import os
import sys
import config
import src.database as database
from src.parser   import parse_log_file
from src.analyzer import run_all_detections
from src.reporter import generate_report


def setup():
    """Creates necessary directories if they don't exist."""
    os.makedirs("data",     exist_ok=True)
    os.makedirs("database", exist_ok=True)
    os.makedirs("reports",  exist_ok=True)


def main():
    print("=" * 60)
    print("       FAILED LOGIN DETECTOR")
    print("       SOC Analysis Tool v1.0")
    print("       by Matthew Vonroy Magombo")
    print("=" * 60)

    # Step 1: Setup directories
    setup()

    # Step 2: Initialize database
    print("\n[INIT] Setting up database...")
    database.reset_database()   # fresh run each time

    # Step 3: Parse log file (optional path argument: python3 main.py /var/log/auth.log)
    log_path = sys.argv[1] if len(sys.argv) > 1 else config.LOG_FILE_PATH
    parse_results = parse_log_file(log_path)
    if not parse_results:
        print("[ERROR] Could not parse log file. Exiting.")
        return

    # Step 4: Run threat analysis
    run_all_detections()

    # Step 5: Generate report
    generate_report()

    print("\n[DONE] Analysis complete.")


if __name__ == "__main__":
    main()