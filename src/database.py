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


def reset_database():
    """
    Drops and recreates all tables, so every run starts fresh.

    Dropping (instead of DELETE FROM) also means a database file created by
    an older version of this tool, with an older schema, can't break the run.
    """
    conn = get_connection()
    cursor = conn.cursor()
    for table in ("logs", "alerts", "ip_summary"):
        cursor.execute(f"DROP TABLE IF EXISTS {table}")  # fixed names, not user input
    conn.commit()
    conn.close()
    create_tables()


def create_tables():
    """Creates all database tables if they don't exist yet."""
    conn = get_connection()
    cursor = conn.cursor()

    # --- TABLE 1: logs ---
    # Stores every single login attempt from the log file
    # timestamp is "YYYY-MM-DD HH:MM:SS" so it sorts correctly as text
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            ip_address   TEXT NOT NULL,
            username     TEXT NOT NULL,
            status       TEXT NOT NULL,
            auth_method  TEXT,
            invalid_user INTEGER DEFAULT 0,
            port         INTEGER,
            raw_line     TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ip_time ON logs (ip_address, timestamp)')

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
            details         TEXT,
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


def insert_logs(events):
    """
    Inserts parsed events into the logs table in one transaction.
    An event with count=N (rsyslog "message repeated N times") becomes N rows,
    so every query below can simply count rows.
    Returns the number of rows inserted.
    """
    rows = []
    for e in events:
        row = (e['timestamp'], e['ip_address'], e['username'], e['status'],
               e.get('auth_method'), int(e.get('invalid_user', False)),
               e.get('port'), e['raw_line'])
        rows.extend([row] * e.get('count', 1))

    conn = get_connection()
    conn.executemany('''
        INSERT INTO logs (timestamp, ip_address, username, status,
                          auth_method, invalid_user, port, raw_line)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', rows)
    # IMPORTANT: Always use ? placeholders, never f-strings for SQL
    # f-strings are vulnerable to SQL injection attacks
    # ? tells SQLite to safely escape the values
    conn.commit()
    conn.close()
    return len(rows)


def rebuild_ip_summary():
    """
    Recomputes ip_summary from the logs table with one GROUP BY query.
    Cheaper and simpler than updating a row for every log line.
    """
    conn = get_connection()
    conn.execute("DELETE FROM ip_summary")
    conn.execute('''
        INSERT INTO ip_summary
            (ip_address, total_attempts, failed_attempts, success_attempts,
             unique_usernames, first_seen, last_seen)
        SELECT
            ip_address,
            COUNT(*),
            SUM(status = 'FAILED'),
            SUM(status = 'SUCCESS'),
            COUNT(DISTINCT username),
            MIN(timestamp),
            MAX(timestamp)
        FROM logs
        GROUP BY ip_address
    ''')
    conn.commit()
    conn.close()


def flag_ip(ip_address):
    """Marks an IP as flagged in the summary (shown as << FLAGGED in the report)."""
    conn = get_connection()
    conn.execute("UPDATE ip_summary SET is_flagged = 1 WHERE ip_address = ?", (ip_address,))
    conn.commit()
    conn.close()


def insert_alert(ip_address, alert_type, severity, failed_count,
                 usernames_tried, first_seen, last_seen, details=None):
    """Saves a generated alert to the database."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO alerts
        (ip_address, alert_type, severity, failed_count,
         usernames_tried, first_seen, last_seen, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ip_address, alert_type, severity, failed_count,
          usernames_tried, first_seen, last_seen, details))

    conn.commit()
    conn.close()


def get_all_logs():
    """Retrieves all log entries."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp, id")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_logs_by_ip():
    """
    Returns {ip_address: [rows in time order]} for every IP.
    The analyzer walks these timelines to find bursts and compromises.
    """
    timelines = {}
    for row in get_all_logs():
        timelines.setdefault(row['ip_address'], []).append(row)
    return timelines


def get_all_alerts():
    """Retrieves all generated alerts, most severe first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM alerts
        ORDER BY CASE severity
                     WHEN 'CRITICAL' THEN 0
                     WHEN 'HIGH'     THEN 1
                     WHEN 'MEDIUM'   THEN 2
                     ELSE 3
                 END,
                 failed_count DESC, id
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_ip_summary():
    """Retrieves the full IP summary table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM ip_summary
        ORDER BY failed_attempts DESC, ip_address
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows
