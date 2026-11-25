with open("/home/nkululeko/cyber-guard/auth_db.py", "r") as f:
    code = f.read()

old_func = """def verify_domain_txt(domain: str) -> bool:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    row = conn.execute("SELECT id, txt_token FROM client_domains WHERE domain = ?", (domain.strip().lower(),)).fetchone()
    if not row:
        conn.close()
        return False
    domain_id, expected_token = row
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            if expected_token in rdata.to_text().strip('"'):
                conn.execute("UPDATE client_domains SET verified = 1 WHERE id = ?", (domain_id,))
                conn.commit()
                conn.close()
                return True
    except Exception:
        pass
    conn.close()
    return False"""

new_func = """def verify_domain_txt(domain: str) -> bool:
    clean_dom = domain.strip().lower()
    with sqlite3.connect(DB_PATH, timeout=30) as conn:
        row = conn.execute("SELECT id, txt_token FROM client_domains WHERE domain = ?", (clean_dom,)).fetchone()
    if not row:
        return False
    domain_id, expected_token = row
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        answers = resolver.resolve(clean_dom, "TXT")
        for rdata in answers:
            if expected_token in rdata.to_text().strip('"'):
                with sqlite3.connect(DB_PATH, timeout=30) as conn:
                    conn.execute("UPDATE client_domains SET verified = 1 WHERE id = ?", (domain_id,))
                return True
    except Exception:
        pass
    return False"""

assert old_func in code, "Function not found"
with open("/home/nkululeko/cyber-guard/auth_db.py", "w") as f:
    f.write(code.replace(old_func, new_func))
print("Fixed verify_domain_txt lock & added public DNS resolvers (8.8.8.8 / 1.1.1.1)!")
