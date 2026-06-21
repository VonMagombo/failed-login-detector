# src/database.py
import sqlite3
import config

def get_connection():
    """
    Creates and returns a database connection.
    Every function that needs the database calls this first.
    """
    conn = sqlite3.connect(config.DATABASE_PATH)
    # This makes rows return as dictionaries instead of tuples
    # So you can access data by column name: row['ip_address']
    # instead of by position: row[2]
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    """
    Creates all database tables if they don't exist yet.
    Run this once when the program starts.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # --- TABLE 1: logs ---
    # Stores every single login attempt from the log file
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            ip_address  TEXT NOT NULL,
            username    TEXT NOT NULL,
            status      TEXT NOT NULL,
            raw_line    TEXT
        )
    ''')
    # AUTOINCREMENT means the database assigns IDs automatically
    # NOT NULL means the field is required
    # TEXT is the data type for strings in SQLite

    # --- TABLE 2: alerts ---
    # Stores generated alerts when suspicious activity is detected
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address      TEXT NOT NULL,
            alert_type      TEXT NOT NULL,
            severity        TEXT NOT NULL,
            failed_count    INTEGER,
            usernames_tried TEXT,
            first_seen      TEXT,
            last_seen       TEXT,
            created_at      TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # --- TABLE 3: ip_summary ---
    # A summary table — aggregated stats per IP address
    # This is a common pattern: store raw data AND pre-computed summaries
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_summary (
            ip_address      TEXT PRIMARY KEY,
            total_attempts  INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            success_attempts INTEGER DEFAULT 0,
            unique_usernames INTEGER DEFAULT 0,
            first_seen      TEXT,
            last_seen       TEXT,
            is_flagged      INTEGER DEFAULT 0
        )
    ''')

    conn.commit()
    conn.close()
    print("[DB] Tables created successfully")


def insert_log(timestamp, ip_address, username, status, raw_line):
    """
    Inserts a single log entry into the logs table.
    Called by the parser for every line it reads.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO logs (timestamp, ip_address, username, status, raw_line)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, ip_address, username, status, raw_line))
    # IMPORTANT: Always use ? placeholders, never f-strings for SQL
    # f-strings are vulnerable to SQL injection attacks
    # ? tells SQLite to safely escape the values

    conn.commit()
    conn.close()


def update_ip_summary(ip_address, status, username, timestamp):
    """
    Updates the ip_summary table after each log entry.
    Uses INSERT OR REPLACE to handle both new and existing IPs.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # First check if this IP already exists in summary
    cursor.execute(
        "SELECT * FROM ip_summary WHERE ip_address = ?",
        (ip_address,)
    )
    existing = cursor.fetchone()

    if existing is None:
        # New IP — insert fresh record
        failed = 1 if status == "FAILED" else 0
        success = 1 if status == "SUCCESS" else 0
        cursor.execute('''
            INSERT INTO ip_summary 
            (ip_address, total_attempts, failed_attempts, 
             success_attempts, unique_usernames, first_seen, last_seen)
            VALUES (?, 1, ?, ?, 1, ?, ?)
        ''', (ip_address, failed, success, timestamp, timestamp))
    else:
        # Existing IP — update their counts
        failed_increment = 1 if status == "FAILED" else 0
        success_increment = 1 if status == "SUCCESS" else 0

        # Count how many unique usernames this IP has tried
        cursor.execute('''
            SELECT COUNT(DISTINCT username) as unique_count
            FROM logs WHERE ip_address = ?
        ''', (ip_address,))
        unique_count = cursor.fetchone()['unique_count']

        cursor.execute('''
            UPDATE ip_summary SET
                total_attempts   = total_attempts + 1,
                failed_attempts  = failed_attempts + ?,
                success_attempts = success_attempts + ?,
                unique_usernames = ?,
                last_seen        = ?
            WHERE ip_address = ?
        ''', (failed_increment, success_increment,
              unique_count, timestamp, ip_address))

    conn.commit()
    conn.close()


def insert_alert(ip_address, alert_type, severity,
                 failed_count, usernames_tried, first_seen, last_seen):
    """Saves a generated alert to the database."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO alerts 
        (ip_address, alert_type, severity, failed_count, 
         usernames_tried, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (ip_address, alert_type, severity, failed_count,
          usernames_tried, first_seen, last_seen))

    conn.commit()
    conn.close()


def get_all_logs():
    """Retrieves all log entries."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_failed_logins_by_ip():
    """
    Key query: groups failed logins by IP address.
    This is the core detection query.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT 
            ip_address,
            COUNT(*) as failed_count,
            COUNT(DISTINCT username) as unique_usernames,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM logs
        WHERE status = 'FAILED'
        GROUP BY ip_address
        ORDER BY failed_count DESC
    ''')
    # GROUP BY combines all rows with same IP into one row
    # COUNT(*) counts how many rows in each group
    # COUNT(DISTINCT username) counts unique usernames per IP
    # MIN/MAX get earliest and latest timestamps

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_alerts():
    """Retrieves all generated alerts."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_ip_summary():
    """Retrieves the full IP summary table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM ip_summary 
        ORDER BY failed_attempts DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows


def clear_all_tables():
    """Clears all data — useful for re-running the program fresh."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM ip_summary")
    conn.commit()
    conn.close()
    print("[DB] All tables cleared")