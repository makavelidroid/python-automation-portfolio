with open("/home/nkululeko/cyber-guard/cyber_app.py", "r") as f:
    code = f.read()

old_path = 'out_path = f"/home/nkululeko/cyber-guard/report_{safe_dom}.html"'
new_path = 'out_path = f"/home/nkululeko/cyber-guard/assets/reports/report_{safe_dom}.html"'

old_btn = """                def make_export(dom, em, r_data):
                    def _exp(e):
                        saved = export_html_report(dom, em, r_data)
                        status_txt.color = ft.Colors.GREEN_700
                        status_txt.value = f"Audit report saved: {saved}"
                        page.update()
                    return _exp

                action_btns = [ft.OutlinedButton("Save Audit Report (HTML)", icon=ft.Icons.DESCRIPTION, on_click=make_export(domain, owner_email, rep))]"""

new_btn = """                def make_export(dom, em, r_data):
                    def _exp(e):
                        saved = export_html_report(dom, em, r_data)
                        rel_url = f"/reports/{saved.split('/')[-1]}"
                        status_txt.color = ft.Colors.GREEN_700
                        status_txt.value = f"Opened report in browser: {rel_url}"
                        page.launch_url(rel_url)
                        page.update()
                    return _exp

                action_btns = [ft.OutlinedButton("Open / Print PDF Report", icon=ft.Icons.PICTURE_AS_PDF, on_click=make_export(domain, owner_email, rep))]"""

assert old_path in code and old_btn in code, "Target code not found"
code = code.replace(old_path, new_path).replace(old_btn, new_btn)
with open("/home/nkululeko/cyber-guard/cyber_app.py", "w") as f:
    f.write(code)
print("1-Click Browser/PDF Report button wired up!")
