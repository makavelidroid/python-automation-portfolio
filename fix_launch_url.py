import re

with open("/home/nkululeko/cyber-guard/cyber_app.py", "r") as f:
    code = f.read()

pattern = re.compile(
    r"def make_export\(.*?\n.*?action_btns = \[ft\.OutlinedButton\([^\]]+\)\]",
    re.DOTALL
)

replacement = """fname = export_html_report(domain, owner_email, rep)
                action_btns = [ft.OutlinedButton("Open / Print PDF Report", icon=ft.Icons.PICTURE_AS_PDF, url=f"/reports/{fname}")]"""

new_code, count = pattern.subn(replacement, code)
assert count > 0, "Could not match make_export block"
with open("/home/nkululeko/cyber-guard/cyber_app.py", "w") as f:
    f.write(new_code)
print(f"Successfully updated {count} block(s)!")
