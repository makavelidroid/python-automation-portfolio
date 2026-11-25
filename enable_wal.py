import sqlite3

db_path = "/home/nkululeko/cyber-guard/cyber_guard.db"
conn = sqlite3.connect(db_path, timeout=30)
conn.execute("PRAGMA journal_mode=WAL;")
conn.execute("PRAGMA busy_timeout=30000;")
conn.commit()
conn.close()
print("SQLite WAL mode enabled!")
