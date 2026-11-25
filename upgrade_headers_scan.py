with open("/home/nkululeko/cyber-guard/scanner.py", "r") as f:
    code = f.read()

old_func = """def check_security_headers(domain: str) -> dict:
    if not is_valid_domain(domain):
        return {"status": "ERROR", "detail": "Invalid domain format"}
    required = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    try:
        resp = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
        missing = [h for h in required if h not in resp.headers]
        score = max(0, 100 - (len(missing) * 20))
        status = "WARNING" if missing else "OK"
        return {"status": status, "score": f"{score}/100", "missing_headers": missing}
    except Exception as e:
        return {"status": "ERROR", "detail": f"HTTP check failed: {e}"}"""

new_func = """def check_security_headers(domain: str) -> dict:
    if not is_valid_domain(domain):
        return {"status": "ERROR", "detail": "Invalid domain format"}
    required = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=8, allow_redirects=True)
            missing = [h for h in required if h not in resp.headers]
            score = max(0, 100 - (len(missing) * 20))
            server_hdr = resp.headers.get("Server", "Hidden")
            final_scheme = resp.url.split("://")[0].upper()
            note = " (Unencrypted HTTP only!)" if final_scheme == "HTTP" else ""
            status = "CRITICAL" if final_scheme == "HTTP" else ("WARNING" if missing else "OK")
            return {
                "status": status,
                "score": f"{score}/100{note}",
                "server": server_hdr,
                "final_url": resp.url,
                "missing_headers": missing,
            }
        except Exception:
            continue
    return {"status": "ERROR", "detail": "Both HTTPS (443) and HTTP (80) refused or timed out."}"""

assert old_func in code, "Function not found"
with open("/home/nkululeko/cyber-guard/scanner.py", "w") as f:
    f.write(code.replace(old_func, new_func))
print("Upgraded check_security_headers with HTTP fallback & Server fingerprinting!")
