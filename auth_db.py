import os
import secrets
import sqlite3
import bcrypt
import dns.resolver

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cyber_guard.db")

def init_cyber_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('client', 'analyst')),
            alert_phone TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS client_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT UNIQUE NOT NULL,
            txt_token TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            last_report TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()
    os.chmod(DB_PATH, 0o600)

def register_user(email: str, password: str, role: str = "client", alert_phone: str = ""):
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute(
        "INSERT INTO users (email, password_hash, role, alert_phone) VALUES (?, ?, ?, ?)",
        (email.strip().lower(), pw_hash, role, alert_phone.strip())
    )
    conn.commit()
    conn.close()

def authenticate_user(email: str, password: str):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    row = conn.execute("SELECT id, password_hash, role FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode("utf-8"), row[1]):
        return {"user_id": row[0], "email": email.strip().lower(), "role": row[2]}
    return None

def add_client_domain(user_id: int, domain: str) -> str:
    token = f"cyberguard-verify={secrets.token_hex(12)}"
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute(
        "INSERT INTO client_domains (user_id, domain, txt_token, verified) VALUES (?, ?, ?, 0)",
        (user_id, domain.strip().lower(), token)
    )
    conn.commit()
    conn.close()
    return token

def verify_domain_txt(domain: str) -> bool:
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
    return False
