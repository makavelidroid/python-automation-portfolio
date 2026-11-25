with open("/home/nkululeko/cyber-guard/cyber_app.py", "r") as f:
    code = f.read()

old_import = "from scanner import check_ssl_expiry, check_security_headers, run_authorized_port_scan"
new_import = "from scanner import is_valid_domain, check_ssl_expiry, check_security_headers, run_authorized_port_scan"

old_add = """    def on_add_domain(e):
        dom = domain_in.value.strip().lower()
        if not dom:
            return"""

new_add = """    def on_add_domain(e):
        dom = domain_in.value.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
        if not dom:
            return
        if not is_valid_domain(dom):
            status_txt.color = ft.Colors.RED_600
            status_txt.value = "Enter a valid domain name only (e.g. komanidream.abrdns.com), not an email or URL."
            page.update()
            return"""

assert old_import in code and old_add in code, "Target code not found"
code = code.replace(old_import, new_import).replace(old_add, new_add)
with open("/home/nkululeko/cyber-guard/cyber_app.py", "w") as f:
    f.write(code)
print("Domain validation added!")
