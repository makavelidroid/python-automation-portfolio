with open("/home/nkululeko/cyber-guard/run_scans.py", "r") as f:
    code = f.read()

old_imp = "from scanner import check_ssl_expiry, check_security_headers, run_authorized_port_scan"
new_imp = "from scanner import check_ssl_expiry, check_security_headers, run_authorized_port_scan, check_email_security"

old_scan = """    ssl_res = check_ssl_expiry(domain)
    hdr_res = check_security_headers(domain)
    port_res = run_authorized_port_scan(domain, bool(verified))
    report = {"scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "ssl": ssl_res, "headers": hdr_res, "ports": port_res}"""

new_scan = """    ssl_res = check_ssl_expiry(domain)
    hdr_res = check_security_headers(domain)
    port_res = run_authorized_port_scan(domain, bool(verified))
    email_res = check_email_security(domain)
    report = {"scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "ssl": ssl_res, "headers": hdr_res, "ports": port_res, "email_sec": email_res}"""

assert old_imp in code and old_scan in code, "Target lines not found"
code = code.replace(old_imp, new_imp).replace(old_scan, new_scan)
with open("/home/nkululeko/cyber-guard/run_scans.py", "w") as f:
    f.write(code)
print("run_scans.py updated with SPF & DMARC checks!")
