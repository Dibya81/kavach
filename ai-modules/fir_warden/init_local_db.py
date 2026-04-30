import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).parent / "kavach_local.db"

def init_local_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT,
        badge_number TEXT,
        role TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # FIRs Table (Upgraded for Police Workflow)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS firs (
        id TEXT PRIMARY KEY,
        fir_number TEXT UNIQUE,
        station_code TEXT,
        district TEXT,
        state TEXT,
        filed_by TEXT,
        complainant_name TEXT,
        incident_date TEXT,
        incident_location TEXT,
        category TEXT,
        severity TEXT,
        priority TEXT DEFAULT 'LOW',
        risk_score REAL DEFAULT 0,
        description TEXT,
        status TEXT DEFAULT 'open',
        blockchain_hash TEXT,
        image_url TEXT,
        workflow_status TEXT DEFAULT 'PENDING',
        rejection_reason TEXT,
        reviewed_by_name TEXT,
        reviewed_at TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(filed_by) REFERENCES users(id)
    )
    ''')

    # FIR Audit Table (Immutable History)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS fir_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fir_id TEXT,
        action TEXT,
        previous_status TEXT,
        new_status TEXT,
        performed_by TEXT,
        reason TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(fir_id) REFERENCES firs(id)
    )
    ''')

    # Sentinel Detections Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sentinel_detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detection_type TEXT,
        confidence REAL,
        location TEXT,
        image_path TEXT,
        metadata_json TEXT,
        risk_level TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # FIR Versions Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS fir_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fir_id TEXT,
        version_number INTEGER,
        changed_by TEXT,
        change_type TEXT,
        diff_snapshot TEXT,
        change_summary TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(fir_id) REFERENCES firs(id)
    )
    ''')

    # Audit Log Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        detail TEXT,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Events Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        summary TEXT,
        occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        detail TEXT,
        severity TEXT
    )
    ''')

    # IP Log Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ip_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        city TEXT,
        country TEXT,
        latitude REAL,
        longitude REAL,
        risk_level TEXT,
        geo TEXT,
        flagged BOOLEAN DEFAULT 0,
        logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Transactions Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id TEXT UNIQUE,
        account_id TEXT,
        amount REAL,
        channel TEXT,
        ip_address TEXT,
        status TEXT,
        fraud_score REAL,
        risk_level TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Blockchain Records Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blockchain_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reference_id TEXT,
        record_type TEXT,
        tx_hash TEXT,
        data_hash TEXT,
        block_number INTEGER,
        network TEXT,
        status TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # KYC Documents Table (for Doc-Guard)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS kyc_documents (
        doc_id TEXT PRIMARY KEY,
        filename TEXT,
        original_text TEXT,
        hash TEXT,
        image_data TEXT,
        timestamp TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Seed Data for Demo
    cursor.execute("SELECT COUNT(*) FROM ip_log")
    if cursor.fetchone()[0] == 0:
        print("[DB] Seeding Demo IP Logs...")
        seed_ips = [
            ("103.21.164.5", "Mumbai", "India", 19.0760, 72.8777, "low", 0),
            ("45.112.124.1", "Jakarta", "Indonesia", -6.2088, 106.8456, "high", 1),
            ("1.1.1.1", "Sydney", "Australia", -33.8688, 151.2093, "info", 0),
            ("8.8.8.8", "Mountain View", "USA", 37.3861, -122.0839, "low", 0),
            ("185.199.108.153", "Paris", "France", 48.8566, 2.3522, "medium", 0)
        ]
        cursor.executemany("INSERT INTO ip_log (ip_address, city, country, latitude, longitude, risk_level, flagged) VALUES (?, ?, ?, ?, ?, ?, ?)", seed_ips)

    cursor.execute("SELECT COUNT(*) FROM transactions")
    if cursor.fetchone()[0] == 0:
        print("[DB] Seeding Demo Transactions...")
        seed_txs = [
            ("TXN-9901", "ACC-4521", 12500.0, "Mobile", "45.112.124.1", "flagged", 88.5, "high"),
            ("TXN-9902", "ACC-1120", 450.0, "Web", "103.21.164.5", "approved", 12.0, "low"),
            ("TXN-9903", "ACC-8874", 8900.0, "API", "185.199.108.153", "pending", 45.0, "medium")
        ]
        cursor.executemany("INSERT INTO transactions (transaction_id, account_id, amount, channel, ip_address, status, fraud_score, risk_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", seed_txs)

    cursor.execute("SELECT COUNT(*) FROM firs")
    if cursor.fetchone()[0] == 0:
        print("[DB] Seeding Demo FIRs...")
        seed_firs = [
            ("FIR-2024-001", "KAVACH-FIR-001", "STN-DELHI", "New Delhi", "Delhi", "00000000-0000-0000-0000-000000000000", "System", "2026-04-29", "Terminal 3", "Weapon", "CRITICAL", "HIGH", 92.0, "Automatic detection of scissors in restricted area.", "open", "0xabc123...", "https://kavach.ai/demo/threat1.jpg", "APPROVED")
        ]
        cursor.executemany("INSERT INTO firs (id, fir_number, station_code, district, state, filed_by, complainant_name, incident_date, incident_location, category, severity, priority, risk_score, description, status, blockchain_hash, image_url, workflow_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seed_firs)

    conn.commit()
    conn.close()
    print(f"[DB] Local SQLite initialized and seeded at {DB_PATH}")

if __name__ == "__main__":
    init_local_db()
