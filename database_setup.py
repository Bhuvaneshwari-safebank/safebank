import sqlite3
import os

def create_user_db():
    if not os.path.exists('database'):
        os.makedirs('database')

    conn = sqlite3.connect('database/user.db')

    # Users Table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            balance INTEGER DEFAULT 1000000,
            is_blocked INTEGER DEFAULT 0,
            unblock_time INTEGER DEFAULT NULL,
            device_info TEXT,
            last_ip TEXT
        )
    ''')

    # Trusted Locations Table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS trusted_locations (
            email TEXT,
            ip TEXT,
            added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ user.db created successfully!")
  

def create_transaction_db():
    conn = sqlite3.connect('database/transaction.db')

    # Transactions Table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT NOT NULL,
            receiver_email TEXT NOT NULL,
            amount INTEGER NOT NULL,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            fraud_score REAL DEFAULT 0.0
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ transaction.db created successfully!")
    print("✅ All user balances set to ₹100000")

if __name__ == "__main__":
    create_user_db()
    create_transaction_db()
