import sqlite3
conn = sqlite3.connect("database.db")
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM satisfaction_ratings")
print(f"Total Ratings: {cursor.fetchone()[0]}")
cursor.execute("SELECT * FROM satisfaction_ratings LIMIT 5")
for row in cursor.fetchall():
    print(row)
conn.close()
