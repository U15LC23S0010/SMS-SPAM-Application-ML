import sqlite3
import os

def init_db():
    db_path = os.getenv("DATABASE_PATH", "database.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # USERS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name TEXT,
        password TEXT,
        country TEXT,
        state TEXT,
        phone TEXT,
        address TEXT,
        otp TEXT,
        emergency_contact TEXT
    )
    """)

    # Column migrations for existing databases
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    if "password" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN password TEXT")
    if "country" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN country TEXT")
    if "emergency_contact" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN emergency_contact TEXT")
    if "whatsapp_number" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN whatsapp_number TEXT")
    if "has_seen_tour" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN has_seen_tour INTEGER DEFAULT 0")
    if "theme" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'default'")
    if "two_factor" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN two_factor INTEGER DEFAULT 0")
    if "sensitivity" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN sensitivity TEXT DEFAULT 'Balanced'")
    if "auto_clear_history" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN auto_clear_history INTEGER DEFAULT 1")
    if "loyalty_points" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN loyalty_points INTEGER DEFAULT 100")
    if "is_admin" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    if "voice_interface" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN voice_interface TEXT DEFAULT 'English + Kannada (Sequential)'")

    # SCANS (unified table for Email, URL, and ID Card scans)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        scan_type TEXT, -- 'email', 'url', 'id_card'
        content TEXT,    -- The text analyzed or filename for ID cards
        prediction TEXT, -- 'Spam'/'Ham' or 'Fake'/'Genuine'
        score INTEGER,
        explanation TEXT,
        explanation_kn TEXT, -- Bilingual explanation
        is_reported INTEGER DEFAULT 0, -- 1 if reported by user
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("PRAGMA table_info(scans)")
    scans_columns = [row[1] for row in cursor.fetchall()]
    if "is_reported" not in scans_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN is_reported INTEGER DEFAULT 0")
    if "explanation_kn" not in scans_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN explanation_kn TEXT")


    # GLOBAL SCAMS (Community DB)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS global_scams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content_hash TEXT UNIQUE,
        content_sample TEXT,
        report_count INTEGER DEFAULT 1,
        last_reported DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # FAMILY CIRCLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS family_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guardian_id INTEGER,
        member_email TEXT,
        relationship TEXT,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(guardian_id) REFERENCES users(id)
    )
    """)

    # SATISFACTION RATINGS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS satisfaction_ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        rating INTEGER, -- 1 to 5
        comment TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cursor.execute('''CREATE TABLE IF NOT EXISTS global_alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        severity TEXT DEFAULT 'warning',
                        active INTEGER DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
    
    conn.commit()
    conn.close()

def get_db():
    db_path = os.getenv("DATABASE_PATH", "database.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn