import sqlite3
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(BASE_DIR, "logs.db")

def create_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, ip_address TEXT, user TEXT,
            action TEXT, status_code INTEGER, details TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, ip_address TEXT, user TEXT,
            action TEXT, details TEXT, risk_type TEXT, risk_level TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, ip_address TEXT, user TEXT,
            action TEXT, details TEXT, risk_type TEXT,
            ai_risk_level TEXT, ai_risk_score INTEGER,
            ai_summary TEXT, ai_why_suspicious TEXT,
            ai_recommended_action TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("Database ready!")

def save_logs(df):
    conn = sqlite3.connect(DB_PATH)
    df.to_sql('logs', conn, if_exists='replace', index=False)
    conn.close()
    print(f"Saved {len(df)} log entries.")

def save_suspicious(events, risk_type, risk_level):
    if len(events) == 0:
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for _, row in events.iterrows():
        cursor.execute("""
            INSERT INTO suspicious_events
            (timestamp, ip_address, user, action, details, risk_type, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            str(row.get('timestamp', '')), row.get('ip_address', ''),
            row.get('user', ''), row.get('action', ''),
            row.get('details', ''), risk_type, risk_level
        ))
    conn.commit()
    conn.close()
    print(f"Saved {len(events)} suspicious events.")

def save_ai_analysis(results):
    if not results:
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for r in results:
        cursor.execute("""
            INSERT INTO ai_analysis
            (timestamp, ip_address, user, action, details, risk_type,
             ai_risk_level, ai_risk_score, ai_summary,
             ai_why_suspicious, ai_recommended_action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r['timestamp'], r['ip_address'], r['user'],
            r['action'], r['details'], r['risk_type'],
            r['ai_risk_level'], r['ai_risk_score'],
            r['ai_summary'], r['ai_why_suspicious'],
            r['ai_recommended_action']
        ))
    conn.commit()
    conn.close()
    print(f"Saved {len(results)} AI analysis results.")

def detect_brute_force(df):
    print("\n=== BRUTE FORCE DETECTION ===")
    failed = df[df['status_code'] == 401].copy()
    ip_counts = failed.groupby('ip_address').size().reset_index(name='fail_count')
    brute_force_ips = ip_counts[ip_counts['fail_count'] >= 3]
    if len(brute_force_ips) == 0:
        print("No brute force attacks detected.")
        return pd.DataFrame()
    print(f"Brute force suspects: {len(brute_force_ips)} IP(s)")
    return failed[failed['ip_address'].isin(brute_force_ips['ip_address'])]

def show_database_summary():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ai_analysis")
    ai_total = cursor.fetchone()[0]
    cursor.execute("SELECT ai_risk_level, COUNT(*) FROM ai_analysis GROUP BY ai_risk_level")
    by_level = cursor.fetchall()
    conn.close()
    print("\n=== DATABASE SUMMARY ===")
    print(f"Total log entries  : {total}")
    print(f"AI analyses saved  : {ai_total}")
    if by_level:
        print("AI Risk breakdown  :")
        for level, count in by_level:
            print(f"  {level}: {count}")