with open("/home/nkululeko/cyber-guard/auth_db.py", "r") as f:
    code = f.read()

old_block = """    if row and bcrypt.checkpw(password.encode("utf-8"), row):
        return {"user_id": row, "email": email.strip().lower(), "role": row}"""

new_block = """    if row and bcrypt.checkpw(password.encode("utf-8"), row[1]):
        return {"user_id": row[0], "email": email.strip().lower(), "role": row[2]}"""

assert old_block in code, "Block not found"
with open("/home/nkululeko/cyber-guard/auth_db.py", "w") as f:
    f.write(code.replace(old_block, new_block))
print("auth_db.py fixed successfully!")
