with open("/home/nkululeko/cyber-guard/run_scans.py", "r") as f:
    code = f.read()

old_imp = "from scanner import check_ssl_expiry, check_security_headers, run_authorized_port_scan, check_email_security"
new_imp = "from scanner import check_ssl_expiry, check_security_headers, run_authorized_port_scan, check_email_security, run_defensive_vuln_checks"

old_block = """    email_res = check_email_security(domain)
    report = {"scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "ssl": ssl_res, "headers": hdr_res, "ports": port_res, "email_sec": email_res}"""

new_block = """    email_res = check_email_security(domain)
    vuln_res = run_defensive_vuln_checks(domain, bool(verified))
    report = {"scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "ssl": ssl_res, "headers": hdr_res, "ports": port_res, "email_sec": email_res, "vulns": vuln_res}"""

old_alert = """    if ssl_res.get("status") == "CRITICAL" or port_res.get("status") == "CRITICAL":
        send_alert(email, phone, domain, f"SSL={ssl_res.get('status')}, Ports={port_res.get('status')}")"""

new_alert = """    if ssl_res.get("status") == "CRITICAL" or port_res.get("status") == "CRITICAL" or vuln_res.get("status") == "CRITICAL":
        send_alert(email, phone, domain, f"SSL={ssl_res.get('status')}, Ports={port_res.get('status')}, Vulns={vuln_res.get('status')}")"""

assert old_imp in code and old_block in code and old_alert in code, "Target lines not found"
code = code.replace(old_imp, new_imp).replace(old_block, new_block).replace(old_alert, new_alert)
with open("/home/nkululeko/cyber-guard/run_scans.py", "w") as f:
    f.write(code)
print("run_scans.py updated with Defensive Vulnerability Checks!")
