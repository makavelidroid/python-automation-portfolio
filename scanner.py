import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
import requests

DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.match(domain.strip().lower()))

def check_ssl_expiry(domain: str) -> dict:
    if not is_valid_domain(domain):
        return {"status": "ERROR", "detail": "Invalid domain format"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        expiry_str = cert["notAfter"]
        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry_dt - datetime.now(timezone.utc)).days
        status = "CRITICAL" if days_left < 14 else "OK"
        return {"status": status, "days_left": days_left, "expires_on": expiry_dt.strftime("%Y-%m-%d")}
    except Exception as e:
        return {"status": "CRITICAL", "detail": f"SSL connection failed: {e}"}

def check_security_headers(domain: str) -> dict:
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
    return {"status": "ERROR", "detail": "Both HTTPS (443) and HTTP (80) refused or timed out."}

def run_authorized_port_scan(domain: str, is_verified: bool) -> dict:
    if not is_verified:
        return {"status": "BLOCKED", "detail": "Domain ownership TXT verification required before port scanning."}
    if not is_valid_domain(domain):
        return {"status": "ERROR", "detail": "Invalid domain format"}
    try:
        result = subprocess.run(
            ["nmap", "-F", "--open", domain],
            capture_output=True, text=True, timeout=45, check=False
        )
        open_ports = [line.strip() for line in result.stdout.splitlines() if "/tcp" in line and "open" in line]
        risky = [p for p in open_ports if any(port in p for port in ["21/tcp", "23/tcp", "445/tcp", "3306/tcp", "3389/tcp", "5432/tcp"])]
        status = "CRITICAL" if risky else "OK"
        return {"status": status, "open_ports": open_ports, "risky_ports": risky}
    except Exception as e:
        return {"status": "ERROR", "detail": f"Nmap error: {e}"}

def check_email_security(domain: str) -> dict:
    if not is_valid_domain(domain):
        return {"status": "ERROR", "detail": "Invalid domain format"}
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    has_spf = False
    has_dmarc = False
    try:
        for rdata in resolver.resolve(domain, "TXT"):
            if "v=spf1" in rdata.to_text().lower():
                has_spf = True
                break
    except Exception:
        pass

    try:
        for rdata in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if "v=dmarc1" in rdata.to_text().lower():
                has_dmarc = True
                break
    except Exception:
        pass

    if has_spf and has_dmarc:
        status = "OK"
    elif has_spf or has_dmarc:
        status = "WARNING"
    else:
        status = "CRITICAL"

    return {
        "status": status,
        "spf": "Configured" if has_spf else "Missing (Domain can be spoofed)",
        "dmarc": "Configured" if has_dmarc else "Missing (No phishing rejection policy)",
    }

def run_defensive_vuln_checks(domain: str, is_verified: bool) -> dict:
    if not is_verified:
        return {"status": "BLOCKED", "detail": "DNS TXT ownership verification required."}
    if not is_valid_domain(domain):
        return {"status": "ERROR", "detail": "Invalid domain format"}

    findings = []
    base_url = None
    resp = None

    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=8, allow_redirects=True)
            base_url = f"{scheme}://{domain}"
            break
        except Exception:
            continue

    if not resp or not base_url:
        return {"status": "ERROR", "detail": "Target web server unreachable on HTTP/HTTPS."}

    # 1. Server / Technology Banner Disclosure
    server_hdr = resp.headers.get("Server", "")
    powered_by = resp.headers.get("X-Powered-By", "")
    if any(ch.isdigit() for ch in server_hdr) or powered_by:
        findings.append(f"Version Disclosure: Server='{server_hdr or 'Hidden'}', X-Powered-By='{powered_by or 'None'}'")

    # 2. Non-Intrusive Sensitive File Exposure Check
    sensitive_paths = [
        ("/.env", ["DB_PASSWORD", "APP_KEY", "SECRET_KEY"]),
        ("/.git/config", ["[core]", "[remote"]),
        ("/phpinfo.php", ["PHP Version", "phpinfo()"]),
    ]
    for path, signatures in sensitive_paths:
        try:
            r = requests.get(base_url + path, timeout=5, allow_redirects=False)
            if r.status_code == 200 and any(sig in r.text for sig in signatures):
                findings.append(f"CRITICAL Exposure: {path} is publicly readable!")
        except Exception:
            pass

    # 3. Weak TLS 1.0 / 1.1 Protocol Probe
    for proto_name, tls_ver in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_ver
            ctx.maximum_version = tls_ver
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    findings.append(f"Deprecated Protocol Enabled: {proto_name} accepted on port 443")
        except Exception:
            pass

    # 4. Cookie Security Flags Check
    raw_cookies = resp.headers.get("Set-Cookie", "")
    if raw_cookies:
        lower_c = raw_cookies.lower()
        missing_flags = [f for f in ("secure", "httponly", "samesite") if f not in lower_c]
        if missing_flags:
            findings.append(f"Weak Cookie Flags: Missing {', '.join(missing_flags)} on Set-Cookie")

    has_crit = any("CRITICAL" in f or "Deprecated" in f for f in findings)
    status = "CRITICAL" if has_crit else ("WARNING" if findings else "OK")
    return {
        "status": status,
        "findings": findings if findings else ["No common misconfigurations or exposed files detected."],
    }
