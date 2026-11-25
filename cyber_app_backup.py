import json
import sqlite3
import urllib.parse
import flet as ft
from auth_db import DB_PATH, init_cyber_db, register_user, authenticate_user, add_client_domain, verify_domain_txt
from run_scans import run_single_domain_scan

def ensure_default_analyst():
    init_cyber_db()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    exists = conn.execute("SELECT id FROM users WHERE role = 'analyst'").fetchone()
    conn.close()
    if not exists:
        register_user("admin@cyberguard.co.za", "CyberAdmin2026!", role="analyst", alert_phone="0710000000")

def get_domains_for_user(user_id: int, role: str):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    if role == "analyst":
        rows = conn.execute("""
            SELECT d.id, d.domain, d.txt_token, d.verified, d.last_report, u.email, u.alert_phone
            FROM client_domains d JOIN users u ON d.user_id = u.id ORDER BY d.id DESC
        """).fetchall()
    else:
        rows = conn.execute("""
            SELECT d.id, d.domain, d.txt_token, d.verified, d.last_report, u.email, u.alert_phone
            FROM client_domains d JOIN users u ON d.user_id = u.id WHERE d.user_id = ? ORDER BY d.id DESC
        """, (user_id,)).fetchall()
    conn.close()
    return rows

def delete_client_domain(domain_id: int):
    with sqlite3.connect(DB_PATH, timeout=30) as conn:
        conn.execute("DELETE FROM client_domains WHERE id = ?", (domain_id,))

def export_html_report(domain: str, owner_email: str, rep: dict) -> str:
    safe_dom = domain.replace(".", "_")
    out_path = f"/home/nkululeko/cyber-guard/assets/reports/report_{safe_dom}.html"
    ssl_i = rep.get("ssl", {})
    hdr_i = rep.get("headers", {})
    prt_i = rep.get("ports", {})
    eml_i = rep.get("email_sec", {})
    vln_i = rep.get("vulns", {})

    ssl_fix = "<div class='fix'><strong>How to Fix:</strong> Install a free Let's Encrypt SSL certificate (Certbot) or proxy your domain through Cloudflare SSL/TLS and enforce HTTPS redirects.</div>" if ssl_i.get("status") != "OK" else ""
    hdr_fix = "<div class='fix'><strong>How to Fix:</strong> Configure your web server (Nginx/Apache/Cloudflare Transform Rules) to send Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options headers.</div>" if hdr_i.get("status") != "OK" else ""
    prt_fix = "<div class='fix'><strong>How to Fix:</strong> Restrict risky database/admin ports (3306, 5432, 3389, 445) using UFW firewall rules so only trusted office/VPN IPs can reach them.</div>" if prt_i.get("status") != "OK" else ""
    eml_fix = "<div class='fix'><strong>How to Fix:</strong> Add a DNS TXT record for SPF (e.g., <code>v=spf1 include:_://google.com -all</code>) and a <code>_dmarc</code> TXT record (<code>v=DMARC1; p=quarantine;</code>) to stop scammers spoofing your company emails.</div>" if eml_i.get("status") != "OK" else ""
    vln_fix = "<div class='fix'><strong>How to Fix:</strong> Block public web access to <code>.env</code> and <code>.git</code> files in Nginx/Apache, disable TLS 1.0/1.1, hide exact software version headers, and add <code>Secure; HttpOnly; SameSite=Lax</code> to cookies.</div>" if vln_i.get("status") != "OK" else ""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cyber-Guard SA Audit - {domain}</title>
<style>body{{font-family:Arial,sans-serif;max-width:740px;margin:40px auto;padding:20px;color:#1e293b}}
.hdr{{background:#0f172a;color:#fff;padding:22px;border-radius:12px}}.card{{border:1px solid #cbd5e1;padding:16px;border-radius:10px;margin-top:16px}}
.crit{{color:#dc2626;font-weight:bold}}.ok{{color:#16a34a;font-weight:bold}}
.fix{{background:#fef3c7;border-left:4px solid #d97706;padding:10px 12px;margin-top:10px;font-size:13px;border-radius:4px}}</style></head>
<body><div class="hdr"><h1>CYBER-GUARD SA • Defensive Security Audit</h1>
<p>Target Domain: <strong>{domain}</strong> | Authorized Owner: {owner_email}</p>
<p>Scan Timestamp: {rep.get('scanned_at')}</p></div>
<div class="card"><h3>1. SSL/TLS Certificate Health</h3>
<p>Status: <span class="{'ok' if ssl_i.get('status')=='OK' else 'crit'}">{ssl_i.get('status')}</span></p>
<p>Details: {ssl_i.get('days_left', ssl_i.get('detail'))}</p>{ssl_fix}</div>
<div class="card"><h3>2. HTTP Security Headers Audit</h3>
<p>Score: <strong>{hdr_i.get('score', 'N/A')}</strong></p>
<p>Missing Headers: {', '.join(hdr_i.get('missing_headers', [])) or hdr_i.get('detail', 'None')}</p>{hdr_fix}</div>
<div class="card"><h3>3. Authorized Network Port Exposure</h3>
<p>Status: <span class="{'ok' if prt_i.get('status')=='OK' else 'crit'}">{prt_i.get('status')}</span></p>
<p>Open Services: {', '.join(prt_i.get('open_ports', [])) or 'None detected'}</p>{prt_fix}</div>
<div class="card"><h3>4. Email Spoofing & Phishing Protection (SPF & DMARC)</h3>
<p>Status: <span class="{'ok' if eml_i.get('status')=='OK' else 'crit'}">{eml_i.get('status', 'Not scanned yet')}</span></p>
<p>SPF Record: {eml_i.get('spf', 'N/A')} | DMARC Record: {eml_i.get('dmarc', 'N/A')}</p>{eml_fix}</div>
<div class="card"><h3>5. Web Misconfigurations & Passive Vulnerability Audit</h3>
<p>Status: <span class="{'ok' if vln_i.get('status')=='OK' else 'crit'}">{vln_i.get('status', 'Not scanned yet')}</span></p>
<p>Findings: {' | '.join(vln_i.get('findings', [])) or vln_i.get('detail', 'Run new scan')}</p>{vln_fix}</div>
<p style="margin-top:30px;font-size:12px;color:#64748b">Generated by CYBER-GUARD SA • POPIA & Cybercrimes Act Aligned Defensive Assessment</p>
</body></html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    import os; return os.path.basename(out_path)

def main(page: ft.Page):
    ensure_default_analyst()
    page.title = "CYBER-GUARD SA • Defensive Security Portal"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.bgcolor = ft.Colors.BLUE_GREY_50
    page.padding = 16
    page.scroll = ft.ScrollMode.AUTO

    session = {"user_id": None, "email": "", "role": ""}
    email_in = ft.TextField(label="Work Email", prefix_icon=ft.Icons.EMAIL_OUTLINED, border_radius=12, filled=True, bgcolor=ft.Colors.WHITE)
    pass_in = ft.TextField(label="Password", password=True, can_reveal_password=True, prefix_icon=ft.Icons.LOCK_OUTLINE, border_radius=12, filled=True, bgcolor=ft.Colors.WHITE)
    phone_in = ft.TextField(label="Alert WhatsApp Number (for new accounts)", hint_text="e.g. 071 234 5678", prefix_icon=ft.Icons.PHONE_ANDROID, border_radius=12, filled=True, bgcolor=ft.Colors.WHITE)
    popia_box = ft.Checkbox(label="POPIA & Cybercrimes Act: I confirm I own or have written authorization to monitor the domains I register.", value=False)
    status_txt = ft.Text("", color=ft.Colors.RED_600, size=13)
    domain_in = ft.TextField(label="Add Client Domain", hint_text="e.g. example.co.za", prefix_icon=ft.Icons.LANGUAGE, border_radius=12, filled=True, bgcolor=ft.Colors.WHITE, expand=True)
    domains_col = ft.Column(spacing=12)

    def wrap(items):
        return ft.Row([ft.Container(content=ft.Column(items, spacing=14), width=560, expand=True)], alignment=ft.MainAxisAlignment.CENTER)

    def render_domains():
        domains_col.controls.clear()
        for d_id, domain, token, verified, raw_rep, owner_email, owner_phone in get_domains_for_user(session["user_id"], session["role"]):
            rep = json.loads(raw_rep) if raw_rep else None
            badge = ft.Container(
                content=ft.Text("VERIFIED" if verified else "DNS TXT PENDING", size=10, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                bgcolor=ft.Colors.GREEN_700 if verified else ft.Colors.ORANGE_700,
                padding=ft.Padding.symmetric(horizontal=8, vertical=3), border_radius=8
            )

            def make_verify(dom):
                def _verify(e):
                    ok = verify_domain_txt(dom)
                    status_txt.color = ft.Colors.GREEN_700 if ok else ft.Colors.RED_600
                    status_txt.value = f"{dom} verified!" if ok else f"TXT record not found yet on {dom}. Add: {token}"
                    render_domains()
                return _verify

            def make_scan(did, dom, ver, em, ph):
                def _scan(e):
                    status_txt.color = ft.Colors.BLUE_800
                    status_txt.value = f"Scanning {dom} (SSL, Headers, Authorized Nmap)..."
                    page.update()
                    run_single_domain_scan(did, dom, bool(ver), em, ph)
                    status_txt.color = ft.Colors.GREEN_700
                    status_txt.value = f"Scan complete for {dom}."
                    render_domains()
                return _scan

            def make_delete(did, dom):
                def _del(e):
                    delete_client_domain(did)
                    status_txt.color = ft.Colors.ORANGE_800
                    status_txt.value = f"Removed {dom}."
                    render_domains()
                return _del

            body = [
                ft.Row([
                    ft.Text(domain, size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_900, expand=True),
                    badge,
                    ft.IconButton(icon=ft.Icons.DELETE_OUTLINE, icon_color=ft.Colors.RED_600, tooltip="Remove Domain", on_click=make_delete(d_id, domain))
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Text(f"Owner: {owner_email}", size=11, color=ft.Colors.GREY_700),
            ]
            if not verified:
                body.append(ft.Text(f"Add DNS TXT record: {token}", size=12, color=ft.Colors.ORANGE_900, selectable=True))
                body.append(ft.Button("Verify DNS TXT Ownership", icon=ft.Icons.VERIFIED, on_click=make_verify(domain), bgcolor=ft.Colors.ORANGE_700, color=ft.Colors.WHITE))
            else:
                body.append(ft.Button("Run Defensive Scan Now", icon=ft.Icons.SECURITY, on_click=make_scan(d_id, domain, verified, owner_email, owner_phone), bgcolor=ft.Colors.BLUE_800, color=ft.Colors.WHITE))

            if rep:
                ssl_info = rep.get("ssl", {})
                hdr_info = rep.get("headers", {})
                prt_info = rep.get("ports", {})
                clean_ph = "".join(ch for ch in (owner_phone or "") if ch.isdigit())
                if clean_ph.startswith("0"):
                    clean_ph = "27" + clean_ph[1:]
                wa_msg = urllib.parse.quote(f"Cyber-Guard Report ({domain}): SSL={ssl_info.get('status')}, Headers={hdr_info.get('score')}, Ports={prt_info.get('status')}")
                body.extend([
                    ft.Divider(height=8),
                    ft.Text(f"Last Scan: {rep.get('scanned_at')}", size=11, color=ft.Colors.GREY_600),
                    ft.Text(f"• SSL Status: {ssl_info.get('status')} ({f"{ssl_info['days_left']} days left" if "days_left" in ssl_info else ssl_info.get("detail", "Unavailable")})", size=13),
                    ft.Text(f"• Security Headers: {hdr_info.get('score', hdr_info.get('detail'))}", size=13),
                    ft.Text(f"• Open Ports: {', '.join(prt_info.get('open_ports', [])) or prt_info.get('detail', 'None')}", size=13),
                    ft.Text(f"• Email Spoofing (SPF/DMARC): {rep.get('email_sec', {}).get('status', 'Run new scan')}", size=13),
                    ft.Text(f"• Web Vulnerabilities: {rep.get('vulns', {}).get('status', 'Run new scan')}", size=13),
                ])
                fname = export_html_report(domain, owner_email, rep)
                action_btns = [ft.OutlinedButton("Open / Print PDF Report", icon=ft.Icons.PICTURE_AS_PDF, url=f"/reports/{fname}")]
                if clean_ph:
                    action_btns.append(ft.TextButton("Send via WhatsApp →", url=f"https://wa.me{clean_ph}?text={wa_msg}"))
                body.append(ft.Row(action_btns, wrap=True))

            domains_col.controls.append(ft.Container(content=ft.Column(body, spacing=6), padding=14, bgcolor=ft.Colors.WHITE, border_radius=14, border=ft.Border.all(1, ft.Colors.BLUE_GREY_100)))
        page.update()

    def on_add_domain(e):
        dom = domain_in.value.strip().lower()
        if not dom:
            return
        try:
            tok = add_client_domain(session["user_id"], dom)
            domain_in.value = ""
            status_txt.color = ft.Colors.BLUE_800
            status_txt.value = f"Added {dom}. Add TXT record: {tok}"
            render_domains()
        except Exception as ex:
            status_txt.color = ft.Colors.RED_600
            status_txt.value = f"Could not add domain: {ex}"
            page.update()

    def show_dashboard():
        page.clean()
        status_txt.value = ""
        render_domains()
        page.add(wrap([
            ft.Row([ft.Text(f"CYBER-GUARD ({session['role'].upper()})", size=22, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_900), ft.IconButton(icon=ft.Icons.LOGOUT, on_click=lambda e: show_login())], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Text(f"Signed in as: {session['email']}", size=12, color=ft.Colors.GREY_700),
            ft.Row([domain_in, ft.IconButton(icon=ft.Icons.ADD_CIRCLE, icon_color=ft.Colors.BLUE_800, icon_size=34, on_click=on_add_domain)]),
            status_txt, domains_col
        ]))
        page.update()

    def do_login(e):
        user = authenticate_user(email_in.value, pass_in.value)
        if not user:
            status_txt.color = ft.Colors.RED_600
            status_txt.value = "Invalid email or password."
            page.update()
            return
        session.update(user)
        show_dashboard()

    def do_register(e):
        if not email_in.value.strip() or len(pass_in.value) < 8:
            status_txt.color = ft.Colors.RED_600
            status_txt.value = "Enter a valid email and a password of at least 8 characters."
            page.update()
            return
        if not popia_box.value:
            status_txt.color = ft.Colors.RED_600
            status_txt.value = "Please accept the POPIA & Cybercrimes Act authorization box."
            page.update()
            return
        try:
            register_user(email_in.value, pass_in.value, role="client", alert_phone=phone_in.value)
            status_txt.color = ft.Colors.GREEN_700
            status_txt.value = "Client account created! Click Sign In now."
        except Exception:
            status_txt.color = ft.Colors.RED_600
            status_txt.value = "That email is already registered."
        page.update()

    def show_login():
        page.clean()
        hero = ft.Container(
            content=ft.Column([
                ft.Row([ft.Icon(ft.Icons.SHIELD_ROUNDED, color=ft.Colors.CYAN_300, size=32), ft.Text("CYBER-GUARD SA", size=26, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE)], spacing=8),
                ft.Text("Defensive SSL, Security Headers & Authorized Port Monitoring for South African Businesses.", size=13, color=ft.Colors.BLUE_100),
            ], spacing=6),
            padding=20, border_radius=16, gradient=ft.LinearGradient(begin=ft.Alignment(-1, -1), end=ft.Alignment(1, 1), colors=[ft.Colors.BLUE_GREY_900, ft.Colors.BLUE_900])
        )
        card = ft.Container(
            content=ft.Column([
                ft.Text("Client & Analyst Portal", size=18, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_900),
                email_in, pass_in, phone_in, popia_box, status_txt,
                ft.Row([
                    ft.Button("Sign In", on_click=do_login, bgcolor=ft.Colors.BLUE_800, color=ft.Colors.WHITE, expand=True),
                    ft.OutlinedButton("Create Client Account", on_click=do_register, expand=True),
                ], spacing=10)
            ], spacing=12),
            padding=20, bgcolor=ft.Colors.WHITE, border_radius=16, border=ft.Border.all(1, ft.Colors.BLUE_GREY_100)
        )
        page.add(wrap([hero, card]))
        page.update()

    show_login()

ft.run(main)
