# report.py
# Week 4: Auto-generate a PDF risk report from our database
# This is the "client deliverable" - what you'd hand to a company

import sqlite3
import os
from datetime import datetime
from fpdf import FPDF

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(BASE_DIR, "logs.db")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")


class RiskReport(FPDF):
    """
    Custom PDF class.
    FPDF lets us build a PDF page by page, line by line.
    Think of it like typing into a Word document with code.
    """

    def header(self):
        """This runs automatically at the top of every page."""
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, 'AI-Powered Audit Log Risk Report', align='R')
        self.ln(4)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        """This runs automatically at the bottom of every page."""
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'Page {self.page_no()} | Confidential', align='C')


def get_data_from_db():
    """Pull all the data we need from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total logs
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    # Suspicious events count
    cursor.execute("SELECT COUNT(*) FROM suspicious_events")
    total_suspicious = cursor.fetchone()[0]

    # AI analysis results
    cursor.execute("""
        SELECT user, action, timestamp, ip_address, 
               risk_type, ai_risk_level, ai_risk_score,
               ai_summary, ai_recommended_action
        FROM ai_analysis
        ORDER BY ai_risk_score DESC
    """)
    ai_results = cursor.fetchall()

    # Risk breakdown
    cursor.execute("""
        SELECT risk_type, COUNT(*) 
        FROM suspicious_events 
        GROUP BY risk_type
    """)
    risk_breakdown = cursor.fetchall()

    conn.close()
    return total_logs, total_suspicious, ai_results, risk_breakdown


def generate_report():
    """Build the full PDF report."""

    # Get data from database
    total_logs, total_suspicious, ai_results, risk_breakdown = get_data_from_db()

    # Create PDF object
    pdf = RiskReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── TITLE SECTION ──
    pdf.set_font('Helvetica', 'B', 24)
    pdf.set_text_color(30, 30, 60)
    pdf.ln(8)
    pdf.cell(0, 12, 'Security Audit Risk Report', align='C')
    pdf.ln(10)

    pdf.set_font('Helvetica', '', 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f'Generated: {datetime.now().strftime("%B %d, %Y at %H:%M")}', align='C')
    pdf.ln(6)
    pdf.cell(0, 6, 'Prepared by: AI-Powered Log Analyzer Pipeline', align='C')
    pdf.ln(12)

    # Divider line
    pdf.set_draw_color(155, 93, 229)
    pdf.set_line_width(0.8)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(10)

    # ── EXECUTIVE SUMMARY ──
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(30, 30, 60)
    pdf.cell(0, 8, 'Executive Summary', align='L')
    pdf.ln(8)

    # Summary boxes
    box_data = [
        ('Total Log Entries', str(total_logs), (0, 187, 249)),
        ('Suspicious Events', str(total_suspicious), (255, 107, 157)),
        ('AI Analyses Done', str(len(ai_results)), (155, 93, 229)),
    ]

    box_width = 58
    box_height = 22
    start_x = 15

    for i, (label, value, color) in enumerate(box_data):
        x = start_x + i * (box_width + 5)
        pdf.set_fill_color(*color)
        pdf.set_xy(x, pdf.get_y())
        pdf.rect(x, pdf.get_y(), box_width, box_height, style='F')
        pdf.set_xy(x, pdf.get_y() + 3)
        pdf.set_font('Helvetica', 'B', 18)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(box_width, 8, value, align='C')
        pdf.set_xy(x, pdf.get_y() + 8)
        pdf.set_font('Helvetica', '', 8)
        pdf.cell(box_width, 5, label, align='C')

    pdf.ln(30)

    # ── RISK BREAKDOWN ──
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(30, 30, 60)
    pdf.cell(0, 8, 'Risk Type Breakdown', align='L')
    pdf.ln(8)

    for risk_type, count in risk_breakdown:
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(60, 60, 60)
        pdf.set_fill_color(245, 245, 250)
        pdf.cell(120, 7, f'  {risk_type}', fill=True)
        pdf.set_fill_color(155, 93, 229)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(30, 7, str(count) + ' events', fill=True, align='C')
        pdf.ln(8)

    pdf.ln(6)

    # ── AI ANALYSIS RESULTS ──
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(30, 30, 60)
    pdf.cell(0, 8, 'AI Risk Analysis - Detailed Findings', align='L')
    pdf.ln(8)

    if not ai_results:
        pdf.set_font('Helvetica', 'I', 10)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 8, 'No AI analysis results found in database.', align='L')
        pdf.ln(8)
    else:
        for i, row in enumerate(ai_results):
            user, action, timestamp, ip, risk_type, ai_level, ai_score, summary, recommendation = row

            # Color based on risk level
            if str(ai_level).lower() == 'high':
                level_color = (220, 50, 50)
                bg_color = (255, 240, 240)
            elif str(ai_level).lower() == 'medium':
                level_color = (200, 120, 0)
                bg_color = (255, 248, 230)
            else:
                level_color = (30, 150, 80)
                bg_color = (240, 255, 245)

            # Event card background
            pdf.set_fill_color(*bg_color)
            card_y = pdf.get_y()

            # Event number + user + action
            pdf.set_font('Helvetica', 'B', 11)
            pdf.set_text_color(30, 30, 60)
            pdf.set_fill_color(*bg_color)
            pdf.cell(0, 7, f'  Event {i+1}: {user} - {action}', fill=True)
            pdf.ln(7)

            # Timestamp + IP
            pdf.set_font('Helvetica', '', 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 5, f'  Timestamp: {timestamp}   |   IP: {ip}   |   Type: {risk_type}', fill=True)
            pdf.ln(6)

            # Risk level badge
            pdf.set_font('Helvetica', 'B', 9)
            pdf.set_text_color(*level_color)
            score_display = str(ai_score) if ai_score else 'N/A'
            pdf.cell(0, 5, f'  Risk Level: {ai_level}   |   Score: {score_display}/10', fill=True)
            pdf.ln(6)

            # Summary
            if summary and summary != 'Analysis failed':
                pdf.set_font('Helvetica', 'I', 9)
                pdf.set_text_color(60, 60, 80)
                # Handle long text
                pdf.multi_cell(0, 5, f'  Summary: {str(summary)[:200]}', fill=True)
                pdf.ln(2)

            # Recommendation
            if recommendation and recommendation != 'Manual review required':
                pdf.set_font('Helvetica', 'B', 9)
                pdf.set_text_color(30, 100, 60)
                pdf.multi_cell(0, 5, f'  Action: {str(recommendation)[:200]}', fill=True)

            pdf.ln(6)
            # Separator line
            pdf.set_draw_color(220, 220, 230)
            pdf.set_line_width(0.3)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(5)

    # ── FOOTER NOTE ──
    pdf.ln(4)
    pdf.set_font('Helvetica', 'I', 9)
    pdf.set_text_color(150, 150, 150)
    pdf.multi_cell(0, 5,
        'This report was automatically generated by an AI-powered audit log analysis pipeline. '
        'All findings should be reviewed by a qualified security professional before action is taken.')

    # ── SAVE THE PDF ──
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"risk_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(OUTPUT_DIR, filename)
    pdf.output(filepath)

    print(f"\n✅ PDF Report generated successfully!")
    print(f"📄 Saved to: {filepath}")
    return filepath


if __name__ == "__main__":
    print("Generating PDF risk report...")
    generate_report()
    print("\nWeek 4 complete! You now have a professional PDF report.")