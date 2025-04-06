import sqlite3
import hashlib

DB_NAME = "users.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    email TEXT UNIQUE,
                    otp_secret TEXT
                )''')
    conn.commit()
    conn.close()

def register_user(username, password, email, otp_secret):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, email, otp_secret) VALUES (?, ?, ?, ?)", 
                  (username, password_hash, email, otp_secret))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def authenticate_user(username, password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT otp_secret FROM users WHERE username=? AND password=?", (username, password_hash))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

init_db()
