# AI-Powered Audit Log Analyzer

An end-to-end AI security pipeline that ingests server logs, detects anomalies, classifies risks using an LLM, and auto-generates professional PDF reports and a live dashboard.

Built by a first-year Data Science and AI student as a portfolio project demonstrating real-world data engineering, AI integration, and automated reporting.

---

## What It Does

Most companies generate thousands of server log entries daily. Security teams manually search for anomalies - this is slow, error-prone, and expensive.

This pipeline automates the entire process:

1. Ingests raw server log data (CSV format)
2. Detects suspicious activity using rule-based flagging (failed logins, after-hours access, brute force attacks, permission violations)
3. Classifies each event using an LLM (Groq/LLaMA) with risk levels: High / Medium / Low
4. Stores all results in a SQLite database permanently
5. Generates a formatted PDF risk report automatically
6. Visualizes everything in a live Streamlit dashboard

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.x |
| Data Processing | Pandas |
| AI / LLM | Groq API (LLaMA 3) |
| Database | SQLite |
| PDF Generation | FPDF2 |
| Dashboard | Streamlit + Matplotlib |

---

## How To Run

Step 1 - Install dependencies

pip install -r requirements.txt

Step 2 - Add your Groq API key to a .env file

GROQ_API_KEY=your_key_here

Step 3 - Run the pipeline

python src/src/ingest.py

Step 4 - Generate PDF report

python src/src/report.py

Step 5 - Launch dashboard

python -m streamlit run src/src/dashboard.py

---

## Sample Output

| Risk Type | Count | Level |
|---|---|---|
| Failed Login | 7 | High |
| Brute Force Attack | 5 | High |
| After Hours Access | 3 | High |
| Permission Denied | 1 | Medium |

---

## Key Concepts Demonstrated

- Data Pipeline Architecture
- LLM Integration as a reasoning engine
- Prompt Engineering for structured JSON output
- Data Persistence with SQLite
- Automated PDF Reporting
- Data Visualization with Streamlit
- Security concepts: brute force detection, anomaly detection, risk classification

---

## Future Extensions

- Natural language query interface
- Email and Slack alerting for High risk events
- Real-time log streaming
- Multi-tenant enterprise support

---

Built with Python, Groq AI, SQLite, Streamlit, and FPDF2