import pandas as pd
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from database import (create_database, save_logs, save_suspicious,
                      detect_brute_force, save_ai_analysis, show_database_summary)
from classifier import analyze_all_suspicious_events

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_FILE = os.path.join(BASE_DIR, "sample_logs", "server_logs.csv")

def load_logs(filepath):
    print(f"Loading logs from: {filepath}")
    df = pd.read_csv(filepath)
    print(f"Loaded {len(df)} log entries.\n")
    return df

if __name__ == "__main__":
    print("Setting up database...")
    create_database()

    df = load_logs(LOG_FILE)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    save_logs(df)

    failed_logins = df[df['status_code'] == 401].copy()
    after_hours = df[df['timestamp'].dt.hour < 6].copy()
    perm_denied = df[df['status_code'] == 403].copy()
    brute_force = detect_brute_force(df)

    save_suspicious(failed_logins, "Failed Login", "High")
    save_suspicious(after_hours, "After Hours Access", "High")
    save_suspicious(perm_denied, "Permission Denied", "Medium")

    after_hours['risk_type'] = 'After Hours Access'
    perm_denied['risk_type'] = 'Permission Denied'
    combined = pd.concat([after_hours, perm_denied], ignore_index=True)

    print(f"\nSending {len(combined)} events to AI...")

    if len(combined) > 0:
        ai_results = analyze_all_suspicious_events(combined)
        save_ai_analysis(ai_results)
    else:
        print("No events to analyze.")

    show_database_summary()
    print("\nWeek 3 complete! Your pipeline now thinks with AI.")