# src/reporter.py
import config
import src.database as database
from datetime import datetime


def get_severity_symbol(severity):
    symbols = {
        "LOW":      "[!]  ",
        "MEDIUM":   "[!!] ",
        "HIGH":     "[!!!]",
        "CRITICAL": "[***]"
    }
    return symbols.get(severity, "[?]")


def generate_report():
    """Generates a full security report and saves it to a file."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    lines.append("=" * 60)
    lines.append("       FAILED LOGIN DETECTOR — SECURITY REPORT")
    lines.append(f"       Generated: {timestamp}")
    lines.append("=" * 60)

    # --- Section 1: Summary ---
    all_logs   = database.get_all_logs()
    all_alerts = database.get_all_alerts()
    ip_summary = database.get_ip_summary()

    total      = len(all_logs)
    failed     = sum(1 for r in all_logs if r['status'] == 'FAILED')
    successful = sum(1 for r in all_logs if r['status'] == 'SUCCESS')

    lines.append("\n[1] SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total login attempts : {total}")
    lines.append(f"  Failed attempts      : {failed}")
    lines.append(f"  Successful logins    : {successful}")
    lines.append(f"  Alerts generated     : {len(all_alerts)}")
    lines.append(f"  Unique IPs seen      : {len(ip_summary)}")

    # --- Section 2: Alerts ---
    lines.append("\n[2] ALERTS")
    lines.append("-" * 40)

    if all_alerts:
        for alert in all_alerts:
            symbol = get_severity_symbol(alert['severity'])
            lines.append(f"\n  {symbol} {alert['severity']} ALERT")
            lines.append(f"     Type       : {alert['alert_type']}")
            lines.append(f"     IP Address : {alert['ip_address']}")
            lines.append(f"     Failures   : {alert['failed_count']}")
            lines.append(f"     Usernames  : {alert['usernames_tried']}")
            lines.append(f"     First seen : {alert['first_seen']}")
            lines.append(f"     Last seen  : {alert['last_seen']}")
    else:
        lines.append("  No alerts generated.")

    # --- Section 3: IP Summary ---
    lines.append("\n[3] IP ADDRESS SUMMARY")
    lines.append("-" * 40)
    lines.append(
        f"  {'IP Address':<18} {'Total':>6} "
        f"{'Failed':>7} {'Success':>8} {'Usernames':>10}"
    )
    lines.append("  " + "-" * 52)

    for row in ip_summary:
        flagged = " << FLAGGED" if row['is_flagged'] else ""
        lines.append(
            f"  {row['ip_address']:<18} "
            f"{row['total_attempts']:>6} "
            f"{row['failed_attempts']:>7} "
            f"{row['success_attempts']:>8} "
            f"{row['unique_usernames']:>10}"
            f"{flagged}"
        )

    # --- Section 4: Recommendations ---
    lines.append("\n[4] RECOMMENDATIONS")
    lines.append("-" * 40)

    if all_alerts:
        flagged_ips = [a['ip_address'] for a in all_alerts]
        lines.append("  Based on the analysis, consider:")
        lines.append("  - Block the following IP addresses at firewall:")
        for ip in set(flagged_ips):
            lines.append(f"      iptables -A INPUT -s {ip} -j DROP")
        lines.append("  - Enable account lockout after 5 failed attempts")
        lines.append("  - Consider deploying fail2ban on SSH service")
        lines.append("  - Review successful logins from flagged IPs")
    else:
        lines.append("  No immediate action required.")

    lines.append("\n" + "=" * 60)
    lines.append("                    END OF REPORT")
    lines.append("=" * 60)

    # Print to terminal
    report_text = "\n".join(lines)
    print(report_text)

    # Save to file
    with open(config.REPORT_PATH, 'w') as f:
        f.write(report_text)

    print(f"\n[REPORT] Saved to: {config.REPORT_PATH}")