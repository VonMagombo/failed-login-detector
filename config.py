# config.py
# Central configuration for the entire system
# Change these values to tune your detection sensitivity

# --- Detection Thresholds ---
FAILED_LOGIN_THRESHOLD = 5      # alert if IP fails this many times
TIME_WINDOW_MINUTES = 10        # within this many minutes
UNIQUE_USERNAMES_THRESHOLD = 3  # alert if IP tries this many different usernames

# --- File Paths ---
LOG_FILE_PATH = "data/auth.log"
DATABASE_PATH = "database/security.db"
REPORT_PATH = "reports/report.txt"

# --- Alert Severity Levels ---
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# --- Thresholds for severity ---
# How many failed attempts = what severity
SEVERITY_THRESHOLDS = {
    SEVERITY_LOW: 3,
    SEVERITY_MEDIUM: 5,
    SEVERITY_HIGH: 10,
    SEVERITY_CRITICAL: 20
}