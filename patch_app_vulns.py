with open("/home/nkululeko/cyber-guard/cyber_app.py", "r") as f:
    code = f.read()

old_vars = """    prt_i = rep.get("ports", {})
    eml_i = rep.get("email_sec", {})"""

new_vars = """    prt_i = rep.get("ports", {})
    eml_i = rep.get("email_sec", {})
    vln_i = rep.get("vulns", {})"""

old_fixes = """    eml_fix = "<div class='fix'><strong>How to Fix:</strong> Add a DNS TXT record for SPF (e.g., <code>v=spf1 include:_://google.com -all</code>) and a <code>_dmarc</code> TXT record (<code>v=DMARC1; p=quarantine;</code>) to stop scammers spoofing your company emails.</div>" if eml_i.get("status") != "OK" else "" """.rstrip()

new_fixes = old_fixes + """
    vln_fix = "<div class='fix'><strong>How to Fix:</strong> Block public web access to <code>.env</code> and <code>.git</code> files in Nginx/Apache, disable TLS 1.0/1.1, hide exact software version headers, and add <code>Secure; HttpOnly; SameSite=Lax</code> to cookies.</div>" if vln_i.get("status") != "OK" else "" """.rstrip()

old_sec4 = """<div class="card"><h3>4. Email Spoofing & Phishing Protection (SPF & DMARC)</h3>
<p>Status: <span class="{'ok' if eml_i.get('status')=='OK' else 'crit'}">{eml_i.get('status', 'Not scanned yet')}</span></p>
<p>SPF Record: {eml_i.get('spf', 'N/A')} | DMARC Record: {eml_i.get('dmarc', 'N/A')}</p>{eml_fix}</div>"""

new_sec4 = old_sec4 + """
<div class="card"><h3>5. Web Misconfigurations & Passive Vulnerability Audit</h3>
<p>Status: <span class="{'ok' if vln_i.get('status')=='OK' else 'crit'}">{vln_i.get('status', 'Not scanned yet')}</span></p>
<p>Findings: {' | '.join(vln_i.get('findings', [])) or vln_i.get('detail', 'Run new scan')}</p>{vln_fix}</div>"""

old_dash = """                    ft.Text(f"• Email Spoofing (SPF/DMARC): {rep.get('email_sec', {}).get('status', 'Run new scan')}", size=13),"""
new_dash = old_dash + """
                    ft.Text(f"• Web Vulnerabilities: {rep.get('vulns', {}).get('status', 'Run new scan')}", size=13),"""

assert old_vars in code and old_sec4 in code and old_dash in code, "Target blocks not found"
code = code.replace(old_vars, new_vars).replace(old_fixes, new_fixes).replace(old_sec4, new_sec4).replace(old_dash, new_dash)
with open("/home/nkululeko/cyber-guard/cyber_app.py", "w") as f:
    f.write(code)
print("Added Section 5 (Web Vulnerabilities) to CYBER-GUARD SA!")
