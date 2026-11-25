import json
import os
import smtplib
import sqlite3
import urllib.parse
from datetime import datetime
from email.message import EmailMessage
from auth_db import DB_PATH, init_cyber_db
from scanner import check_ssl_expiry, check_security_headers, run_authorized_port_scan, check_email_security, run_defensive_vuln_checks

SMTP_HOST = os.getenv("CYBER_SMTP_HOST", "://gmail.com")
SMTP_PORT = int(os.getenv("CYBER_SMTP_PORT", "587"))
SMTP_USER = os.getenv("CYBER_SMTP_USER", "")
SMTP_PASS = os.getenv("CYBER_SMTP_PASS", "")

def send_alert(email: str, phone: str, domain: str, summary: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_phone = "".join(ch for ch in (phone or "") if ch.isdigit())
    if clean_phone.startswith("0"):
        clean_phone = "27" + clean_phone[1:]
    wa_text = urllib.parse.quote(f"CYBER-GUARD ALERT ({domain}): {summary}")
    wa_link = f"https://wa.me{clean_phone}?text={wa_text}" if clean_phone else "No phone set"

    print(f"[ALERT {timestamp}] Domain: {domain} | {summary} | WhatsApp: {wa_link}")

    if SMTP_USER and SMTP_PASS and email:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[CRITICAL] Cyber-Guard Alert for {domain}"
            msg["From"] = SMTP_USER
            msg["To"] = email
            msg.set_content(f"Security Alert at {timestamp}\nDomain: {domain}\nFindings: {summary}\nQuick WhatsApp Escalation: {wa_link}")
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
            print(f"[EMAIL SENT] Alert delivered to {email}")
        except Exception as e:
            print(f"[EMAIL ERROR] Could not send to {email}: {e}")

def run_single_domain_scan(domain_id: int, domain: str, verified: bool, email: str, phone: str) -> dict:
    ssl_res = check_ssl_expiry(domain)
    hdr_res = check_security_headers(domain)
    port_res = run_authorized_port_scan(domain, bool(verified))
    email_res = check_email_security(domain)
    vuln_res = run_defensive_vuln_checks(domain, bool(verified))
    report = {"scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "ssl": ssl_res, "headers": hdr_res, "ports": port_res, "email_sec": email_res, "vulns": vuln_res}

    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("UPDATE client_domains SET last_report = ? WHERE id = ?", (json.dumps(report), domain_id))
    conn.commit()
    conn.close()

    if ssl_res.get("status") == "CRITICAL" or port_res.get("status") == "CRITICAL" or vuln_res.get("status") == "CRITICAL":
        send_alert(email, phone, domain, f"SSL={ssl_res.get('status')}, Ports={port_res.get('status')}, Vulns={vuln_res.get('status')}")
    return report

def run_all_scheduled_scans():
    init_cyber_db()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    rows = conn.execute("""
        SELECT d.id, d.domain, d.verified, u.email, u.alert_phone
        FROM client_domains d
        JOIN users u ON d.user_id = u.id
        WHERE d.verified = 1
    """).fetchall()
    conn.close()
    for domain_id, domain, verified, email, phone in rows:
        run_single_domain_scan(domain_id, domain, bool(verified), email, phone)

if __name__ == "__main__":
    run_all_scheduled_scans()
