import sqlite3
conn = sqlite3.connect("database.db")
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute("SELECT email, name, password, otp FROM users")
rows = cursor.fetchall()
for row in rows:
    print(f"Email: {row['email']}, Name: {row['name']}, OTP: {row['otp']}, HasPassword: {bool(row['password'])}")
conn.close()
