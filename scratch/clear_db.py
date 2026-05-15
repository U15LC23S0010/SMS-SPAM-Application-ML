import sqlite3
import os

db_path = "database.db"
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM scans;")
        cursor.execute("DELETE FROM users;")
        conn.commit()
        print("Successfully removed all users and scan records.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
else:
    print("Database file not found.")
