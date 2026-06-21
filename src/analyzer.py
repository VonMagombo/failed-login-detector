# src/analyzer.py
import config
import src.database as database


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


def detect_brute_force():
    """
    Detects brute force attacks.
    Definition: Same IP failing to login more than threshold times.
    This is the most common attack pattern in SSH logs.
    """
    print("\n[ANALYZER] Running brute force detection...")

    # Get failed login counts grouped by IP from database
    failed_by_ip = database.get_failed_logins_by_ip()
    alerts_generated = 0

    for row in failed_by_ip:
        ip            = row['ip_address']
        failed_count  = row['failed_count']
        unique_users  = row['unique_usernames']
        first_seen    = row['first_seen']
        last_seen     = row['last_seen']

        # Check if this IP exceeds our threshold
        if failed_count >= config.FAILED_LOGIN_THRESHOLD:
            severity = determine_severity(failed_count)

            # Determine what type of attack this looks like
            if unique_users >= config.UNIQUE_USERNAMES_THRESHOLD:
                alert_type = "CREDENTIAL_STUFFING"
                # Credential stuffing = trying many different usernames
                # Attacker has a list of username/password combos
            else:
                alert_type = "BRUTE_FORCE"
                # Brute force = hammering same username with many passwords

            # Get the list of usernames this IP tried
            usernames = get_usernames_for_ip(ip)

            # Save alert to database
            database.insert_alert(
                ip_address     = ip,
                alert_type     = alert_type,
                severity       = severity,
                failed_count   = failed_count,
                usernames_tried = ', '.join(usernames),
                first_seen     = first_seen,
                last_seen      = last_seen
            )

            print(f"  [ALERT] {severity} - {alert_type}")
            print(f"          IP: {ip}")
            print(f"          Failed attempts: {failed_count}")
            print(f"          Usernames tried: {unique_users}")
            alerts_generated += 1

    print(f"[ANALYZER] Alerts generated: {alerts_generated}")
    return alerts_generated


def get_usernames_for_ip(ip_address):
    """Gets all unique usernames an IP address attempted."""
    import sqlite3
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        SELECT DISTINCT username FROM logs
        WHERE ip_address = ? AND status = 'FAILED'
    ''', (ip_address,))

    rows = cursor.fetchall()
    conn.close()
    return [row['username'] for row in rows]


def run_all_detections():
    """Runs all detection methods. Add more here as you build them."""
    print("\n[ANALYZER] Starting threat analysis...")
    total_alerts = 0
    total_alerts += detect_brute_force()
    print(f"[ANALYZER] Total alerts: {total_alerts}")
    return total_alerts 