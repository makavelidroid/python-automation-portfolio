import os
import re
import socket
import ssl
import sqlite3
import secrets
from datetime import datetime
from urllib.parse import urlparse
import bcrypt
import dns.resolver
import requests
import flet as ft

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "cyber_guard.db")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            company_name TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            txt_token TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            last_score INTEGER DEFAULT 0,
            last_grade TEXT DEFAULT 'N/A',
            last_scan_at TEXT DEFAULT 'Never',
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            summary TEXT NOT NULL,
            report_file TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(domain_id) REFERENCES domains(id)
        )
    """)
    conn.commit()
    conn.close()

def clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).netloc
    return raw.split("/")[0].split(":")[0]

def compute_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"

def check_dns_txt(domain: str, expected_token: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt_val = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if expected_token in txt_val:
                return True
    except Exception:
        pass
    return False

def run_defensive_audit(domain: str, owner_email: str) -> dict:
    score = 100
    findings = []

    # 1. SSL/TLS Check
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            exp = cert.get("notAfter", "Valid")
            findings.append(("SSL/TLS Certificate Health", "OK", f"Active TLS certificate verified (Expires: {exp}).", "Keep auto-renewal enabled via Certbot or Cloudflare."))
    except Exception as ex:
        score -= 30
        findings.append(("SSL/TLS Certificate Health", "CRITICAL", f"HTTPS connection failed: {ex}", "Install a free Let's Encrypt SSL certificate or proxy through Cloudflare SSL/TLS."))

    # 2. HTTP Security Headers
    required_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]
    try:
        resp = requests.get(f"https://{domain}", timeout=6, allow_redirects=True)
        headers = resp.headers
        missing = [h for h in required_headers if h not in headers]
        if not missing:
            findings.append(("HTTP Security Headers Audit", "OK", "All 5 core browser protection headers are present.", "Maintain current security header configuration."))
        else:
            penalty = len(missing) * 5
            score -= penalty
            findings.append(("HTTP Security Headers Audit", "WARNING", f"Missing {len(missing)} headers: {', '.join(missing)}", "Configure Nginx/Apache or Cloudflare Transform Rules to enforce missing security headers."))
        server_hdr = headers.get("Server", "Hidden")
        powered_hdr = headers.get("X-Powered-By", "Hidden")
        if any(ch.isdigit() for ch in server_hdr) or powered_hdr != "Hidden":
            score -= 10
            findings.append(("Server Fingerprinting & Exposure", "WARNING", f"Version disclosure detected (Server: {server_hdr}, X-Powered-By: {powered_hdr}).", "Disable server_tokens in Nginx and remove X-Powered-By headers."))
        else:
            findings.append(("Server Fingerprinting & Exposure", "OK", "Software version headers are properly masked.", "No action required."))
    except Exception:
        score -= 15
        findings.append(("HTTP Security Headers Audit", "CRITICAL", "Unable to inspect HTTPS headers (site unreachable over HTTPS).", "Ensure web server is online and listening on port 443."))

    # 3. Email Spoofing (SPF & DMARC)
    spf_ok, dmarc_ok = False, False
    try:
        for r in dns.resolver.resolve(domain, "TXT", lifetime=4):
            if "v=spf1" in b"".join(r.strings).decode("utf-8", errors="ignore").lower():
                spf_ok = True
    except Exception:
        pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=4):
            if "v=dmarc1" in b"".join(r.strings).decode("utf-8", errors="ignore").lower():
                dmarc_ok = True
    except Exception:
        pass

    if spf_ok and dmarc_ok:
        findings.append(("Email Spoofing Protection (SPF & DMARC)", "OK", "Both SPF and DMARC records are active.", "Review DMARC aggregate reports periodically."))
    else:
        score -= 20
        missing_mail = []
        if not spf_ok: missing_mail.append("SPF")
        if not dmarc_ok: missing_mail.append("DMARC")
        findings.append(("Email Spoofing Protection (SPF & DMARC)", "CRITICAL", f"Missing DNS records: {' & '.join(missing_mail)}. Domain can be spoofed in phishing attacks.", "Publish TXT records for SPF (v=spf1 ...) and _dmarc (v=DMARC1; p=quarantine;)."))

    score = max(0, min(100, score))
    grade = compute_grade(score)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M SAST")

    # Generate Executive HTML/PDF-Ready Report
    safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", domain)
    report_filename = f"audit_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join(REPORTS_DIR, report_filename)

    rows_html = ""
    for title, status, detail, fix in findings:
        badge_color = "#16a34a" if status == "OK" else ("#d97706" if status == "WARNING" else "#dc2626")
        rows_html += f"""
        <div style="border:1px solid #e2e8f0; border-radius:10px; padding:16px; margin-bottom:14px; background:#ffffff;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <strong style="font-size:16px; color:#0f172a;">{title}</strong>
                <span style="background:{badge_color}; color:#fff; padding:4px 10px; border-radius:6px; font-size:12px; font-weight:bold;">{status}</span>
            </div>
            <p style="color:#334155; margin:8px 0;">{detail}</p>
            <div style="background:#fefce8; border-left:4px solid #eab308; padding:10px; font-size:13px; color:#713f12;">
                <strong>Remediation Guidance:</strong> {fix}
            </div>
        </div>
        """

    html_doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CYBER-GUARD SA Security Audit - {domain}</title></head>
<body style="font-family:Arial,sans-serif; background:#f8fafc; padding:30px; max-width:820px; margin:auto;">
    <div style="background:#0f172a; color:#fff; padding:26px; border-radius:14px; margin-bottom:20px;">
        <div style="font-size:11px; letter-spacing:1.5px; color:#38bdf8; font-weight:bold;">CYBER-GUARD SA • POPIA & CYBERCRIMES ACT DEFENSIVE AUDIT</div>
        <h1 style="margin:6px 0;">Executive Security Posture Report</h1>
        <p style="margin:4px 0; color:#cbd5e1;">Target Asset: <strong>{domain}</strong> | Authorized Owner: {owner_email}</p>
        <p style="margin:4px 0; color:#94a3b8; font-size:13px;">Assessment Timestamp: {ts} | Security Score: <strong>{score}/100 (Grade {grade})</strong></p>
    </div>
    {rows_html}
    <p style="text-align:center; color:#64748b; font-size:12px; margin-top:24px;">Generated by CYBER-GUARD SA • Developed by NKULULEKO MANGALI • Defensive Non-Intrusive Audit</p>
</body></html>"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

    return {"score": score, "grade": grade, "findings": findings, "report_file": report_filename, "timestamp": ts}

def main(page: ft.Page):
    init_db()
    page.title = "CYBER-GUARD SA • Enterprise Web Security"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.bgcolor = "#F1F5F9"
    page.padding = 16
    page.scroll = ft.ScrollMode.AUTO

    session = {"user_id": None, "email": "", "company": ""}

    footer = ft.Column([
        ft.Text("CYBER-GUARD SA • POPIA & Cybercrimes Act Defensive Compliance Platform", size=11, color=ft.Colors.BLUE_GREY_500),
        ft.Text("Developed by NKULULEKO MANGALI", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_GREY_800),
    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=2)

    def wrap_container(controls, max_w=760):
        return ft.Row([ft.Container(content=ft.Column(controls, spacing=14), width=max_w, expand=True)], alignment=ft.MainAxisAlignment.CENTER)

    def show_auth_screen():
        page.clean()
        email_field = ft.TextField(label="Work Email", hint_text="security@company.co.za", prefix_icon=ft.Icons.EMAIL_OUTLINED, border_radius=10, filled=True, bgcolor=ft.Colors.WHITE)
        pass_field = ft.TextField(label="Password", password=True, can_reveal_password=True, prefix_icon=ft.Icons.LOCK_OUTLINE, border_radius=10, filled=True, bgcolor=ft.Colors.WHITE)
        company_field = ft.TextField(label="Organization / Business Name (For Registration)", hint_text="e.g. Komani Logistics (Pty) Ltd", prefix_icon=ft.Icons.BUSINESS, border_radius=10, filled=True, bgcolor=ft.Colors.WHITE)
        auth_status = ft.Text("", color=ft.Colors.RED_600, size=13, weight=ft.FontWeight.W_500)

        def on_login(e):
            em = email_field.value.strip().lower()
            pw = pass_field.value
            if not em or not pw:
                auth_status.value = "Enter both email and password."
                page.update()
                return
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT id, password_hash, company_name FROM users WHERE email = ?", (em,))
            row = cur.fetchone()
            conn.close()
            if row and bcrypt.checkpw(pw.encode("utf-8"), (row[1] if isinstance(row[1], bytes) else row[1].encode("utf-8"))):
                session.update({"user_id": row[0], "email": em, "company": row[2] or em})
                show_dashboard()
            else:
                auth_status.value = "Invalid email or password."
                page.update()

        def on_register(e):
            em = email_field.value.strip().lower()
            pw = pass_field.value
            comp = company_field.value.strip() or "Enterprise Client"
            if not em or len(pw) < 6:
                auth_status.value = "Provide a valid email and a password of at least 6 characters."
                page.update()
                return
            pw_hash = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            try:
                conn = sqlite3.connect(DB_FILE)
                cur = conn.cursor()
                cur.execute("INSERT INTO users (email, password_hash, company_name, created_at) VALUES (?, ?, ?, ?)", (em, pw_hash, comp, datetime.now().strftime("%Y-%m-%d %H:%M")))
                uid = cur.lastrowid
                conn.commit()
                conn.close()
                session.update({"user_id": uid, "email": em, "company": comp})
                show_dashboard()
            except sqlite3.IntegrityError:
                auth_status.value = "An account with this email already exists."
                page.update()

        hero = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#38BDF8", size=36),
                    ft.Column([
                        ft.Text("CYBER-GUARD SA", size=26, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                        ft.Text("Enterprise Defensive Web & DNS Posture Monitor", size=12, color="#94A3B8"),
                    ], spacing=1)
                ], spacing=12),
                ft.Text("Authorized, non-intrusive security posture audits for South African businesses. Verify domain ownership via DNS TXT and generate executive PDF reports.", size=13, color="#CBD5E1"),
            ], spacing=10),
            padding=24, border_radius=16,
            gradient=ft.LinearGradient(begin=ft.Alignment(-1, -1), end=ft.Alignment(1, 1), colors=["#0F172A", "#1E3A8A"])
        )

        auth_card = ft.Container(
            content=ft.Column([
                ft.Text("Client Security Portal", size=18, weight=ft.FontWeight.BOLD, color="#0F172A"),
                email_field, pass_field, company_field, auth_status,
                ft.Row([
                    ft.Button("Sign In", icon=ft.Icons.LOGIN, on_click=on_login, bgcolor="#0F172A", color=ft.Colors.WHITE, height=46, expand=True),
                    ft.Button("Create Account", icon=ft.Icons.PERSON_ADD, on_click=on_register, bgcolor="#0284C7", color=ft.Colors.WHITE, height=46, expand=True),
                ], spacing=10),
            ], spacing=12),
            padding=22, bgcolor=ft.Colors.WHITE, border_radius=16, border=ft.Border.all(1, "#CBD5E1")
        )

        page.add(wrap_container([hero, auth_card, footer], max_w=540))
        page.update()


    def grade_color(grade: str) -> str:
        return {"A": "#16A34A", "B": "#0284C7", "C": "#D97706", "D": "#EA580C", "F": "#DC2626"}.get(grade, "#64748B")

    def show_dashboard():
        page.clean()
        domain_input = ft.TextField(label="Add Authorized Domain", hint_text="e.g. yourbusiness.co.za", prefix_icon=ft.Icons.LANGUAGE, border_radius=10, filled=True, bgcolor=ft.Colors.WHITE, expand=True)
        dash_msg = ft.Text("", size=13, weight=ft.FontWeight.W_500, color="#0284C7")
        domains_col = ft.Column(spacing=12)
        results_col = ft.Column(spacing=10)

        def on_logout(e):
            session.update({"user_id": None, "email": "", "company": ""})
            show_auth_screen()

        def on_add_domain(e):
            dom = clean_domain(domain_input.value)
            if not dom or "." not in dom:
                dash_msg.value = "Enter a valid root domain (e.g. example.co.za)."
                dash_msg.color = ft.Colors.RED_600
                page.update()
                return
            token = f"cyberguard-verify={secrets.token_hex(8)}"
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("INSERT INTO domains (user_id, domain, txt_token) VALUES (?, ?, ?)", (session["user_id"], dom, token))
            conn.commit()
            conn.close()
            domain_input.value = ""
            dash_msg.value = f"Added {dom}. Publish the DNS TXT record below to authorize scanning."
            dash_msg.color = "#0284C7"
            refresh_domains()

        def render_findings(dom_name: str, res: dict):
            results_col.controls.clear()
            results_col.controls.append(ft.Row([
                ft.Text(f"Latest Findings: {dom_name}", size=17, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text(f"Saved: reports/{res['report_file']}", size=11, color="#0284C7", selectable=True),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN))
            for title, status, detail, fix in res["findings"]:
                st_col = "#16A34A" if status == "OK" else ("#D97706" if status == "WARNING" else "#DC2626")
                results_col.controls.append(ft.Container(
                    content=ft.Column([
                        ft.Row([ft.Text(title, size=14, weight=ft.FontWeight.BOLD, color="#0F172A"), ft.Container(content=ft.Text(status, size=10, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE), bgcolor=st_col, padding=ft.Padding.symmetric(horizontal=8, vertical=3), border_radius=6)], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(detail, size=13, color="#334155"),
                        ft.Container(content=ft.Text(f"How to Fix: {fix}", size=12, color="#713F12"), padding=8, bgcolor="#FEFCE8", border_radius=8),
                    ], spacing=6),
                    padding=14, bgcolor=ft.Colors.WHITE, border_radius=12, border=ft.Border.all(1, "#E2E8F0")
                ))
            page.update()

        def refresh_domains():
            domains_col.controls.clear()
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT id, domain, txt_token, verified, last_score, last_grade, last_scan_at FROM domains WHERE user_id = ? ORDER BY id DESC", (session["user_id"],))
            rows = cur.fetchall()
            conn.close()

            if not rows:
                domains_col.controls.append(ft.Container(content=ft.Text("No domains registered yet. Add your company domain above to begin.", color="#64748B"), padding=18, bgcolor=ft.Colors.WHITE, border_radius=12))

            for dom_id, dom_name, txt_tok, is_ver, l_score, l_grade, l_scan in rows:
                def make_verify_fn(d_id, d_name, tok):
                    def _verify(ev):
                        dash_msg.value = f"Checking DNS TXT records for {d_name}..."
                        dash_msg.color = "#0284C7"
                        page.update()
                        if check_dns_txt(d_name, tok):
                            c = sqlite3.connect(DB_FILE)
                            c.execute("UPDATE domains SET verified = 1 WHERE id = ?", (d_id,))
                            c.commit()
                            c.close()
                            dash_msg.value = f"Ownership verified for {d_name}! You can now run defensive audits."
                            dash_msg.color = "#16A34A"
                            refresh_domains()
                        else:
                            dash_msg.value = f"TXT record '{tok}' not found yet on {d_name}."
                            dash_msg.color = ft.Colors.RED_600
                            page.update()
                    return _verify

                def make_scan_fn(d_id, d_name):
                    def _scan(ev):
                        dash_msg.value = f"Running defensive posture audit on {d_name}..."
                        dash_msg.color = "#0284C7"
                        results_col.controls.clear()
                        page.update()
                        res = run_defensive_audit(d_name, session["email"])
                        c = sqlite3.connect(DB_FILE)
                        c.execute("UPDATE domains SET last_score = ?, last_grade = ?, last_scan_at = ? WHERE id = ?", (res["score"], res["grade"], res["timestamp"], d_id))
                        c.execute("INSERT INTO scans (domain_id, score, grade, summary, report_file, created_at) VALUES (?, ?, ?, ?, ?, ?)", (d_id, res["score"], res["grade"], f"Score {res['score']}/100", res["report_file"], res["timestamp"]))
                        c.commit()
                        c.close()
                        dash_msg.value = f"Audit complete for {d_name}: Score {res['score']}/100 (Grade {res['grade']})"
                        dash_msg.color = "#16A34A"
                        render_findings(d_name, res)
                        refresh_domains()
                    return _scan

                badge_bg = "#DCFCE7" if is_ver else "#FEF3C7"
                badge_fg = "#166534" if is_ver else "#92400E"
                badge_txt = "VERIFIED OWNER" if is_ver else "PENDING DNS TXT"

                card_body = [
                    ft.Row([
                        ft.Row([
                            ft.Container(content=ft.Text(l_grade, size=18, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE), width=42, height=42, bgcolor=grade_color(l_grade), border_radius=10, alignment=ft.Alignment(0, 0)),
                            ft.Column([
                                ft.Text(dom_name, size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                                ft.Text(f"Score: {l_score}/100  •  Last Scan: {l_scan}", size=12, color="#64748B"),
                            ], spacing=2),
                        ], spacing=10),
                        ft.Container(content=ft.Text(badge_txt, size=10, weight=ft.FontWeight.BOLD, color=badge_fg), bgcolor=badge_bg, padding=ft.Padding.symmetric(horizontal=8, vertical=4), border_radius=8),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ]

                if not is_ver:
                    card_body.append(ft.Container(
                        content=ft.Column([
                            ft.Text("Add this TXT record to your domain DNS to prove ownership:", size=12, color="#78350F"),
                            ft.Text(txt_tok, size=12, weight=ft.FontWeight.BOLD, selectable=True, color="#0F172A"),
                            ft.Button("Verify DNS TXT Record", icon=ft.Icons.VERIFIED, on_click=make_verify_fn(dom_id, dom_name, txt_tok), bgcolor="#D97706", color=ft.Colors.WHITE),
                        ], spacing=6),
                        padding=12, bgcolor="#FFFBEB", border_radius=10, border=ft.Border.all(1, "#FCD34D")
                    ))
                else:
                    card_body.append(ft.Row([
                        ft.Button("Run Defensive Audit", icon=ft.Icons.SECURITY, on_click=make_scan_fn(dom_id, dom_name), bgcolor="#0F172A", color=ft.Colors.WHITE),
                    ]))

                domains_col.controls.append(ft.Container(content=ft.Column(card_body, spacing=10), padding=16, bgcolor=ft.Colors.WHITE, border_radius=14, border=ft.Border.all(1, "#CBD5E1")))
            page.update()

        top_bar = ft.Container(
            content=ft.Row([
                ft.Row([ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#38BDF8", size=28), ft.Column([ft.Text("CYBER-GUARD SA", size=18, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE), ft.Text(f"{session['company']} ({session['email']})", size=11, color="#94A3B8")], spacing=1)], spacing=10),
                ft.IconButton(icon=ft.Icons.LOGOUT, icon_color=ft.Colors.WHITE, tooltip="Logout", on_click=on_logout),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            padding=16, border_radius=14, bgcolor="#0F172A"
        )

        add_bar = ft.Container(
            content=ft.Row([domain_input, ft.Button("Add Asset", icon=ft.Icons.ADD, on_click=on_add_domain, bgcolor="#0284C7", color=ft.Colors.WHITE, height=48)], spacing=10),
            padding=14, bgcolor=ft.Colors.WHITE, border_radius=14, border=ft.Border.all(1, "#CBD5E1")
        )

        page.add(wrap_container([top_bar, add_bar, dash_msg, domains_col, results_col, footer]))
        refresh_domains()

    show_auth_screen()

ft.run(main)
