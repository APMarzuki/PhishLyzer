import json
import os
from fpdf import FPDF
from datetime import datetime


class ReportGenerator:
    def __init__(self, output_dir="data"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def save_json(self, data):
        """Saves raw analysis data to a JSON file."""
        filename = f"report_{data['domain']}_{datetime.now().strftime('%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        return filepath

    def save_pdf(self, data):
        """Generates a professional PDF report."""
        pdf = FPDF()
        pdf.add_page()

        # Header
        pdf.set_font("helvetica", "B", 20)
        pdf.cell(0, 10, "PhishLyzer Security Report", ln=True, align="C")
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 10, f"Generated on: {data['timestamp']}", ln=True, align="C")
        pdf.ln(10)

        # Summary Section
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        pdf.set_font("helvetica", "", 12)
        pdf.cell(0, 10, f"Target Domain: {data['domain']}", ln=True)
        pdf.cell(0, 10, f"Domain Age: {data['domain_age_days']} days", ln=True)

        # Risk Score with Color Coding
        score = data['risk_score']
        if score >= 70:
            pdf.set_text_color(255, 0, 0)  # Red
            status = "DANGER"
        elif score >= 30:
            pdf.set_text_color(255, 165, 0)  # Orange
            status = "SUSPICIOUS"
        else:
            pdf.set_text_color(0, 128, 0)  # Green
            status = "SAFE"

        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, f"Risk Score: {score}/100 ({status})", ln=True)
        pdf.set_text_color(0, 0, 0)  # Reset to black
        pdf.ln(5)

        # Intelligence Table
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 10, "2. Intelligence Breakdown", ln=True)

        with pdf.table() as table:
            row = table.row()
            row.cell("Source")
            row.cell("Finding")

            # VirusTotal Row
            vt = data['intel']['virus_total']
            row = table.row()
            row.cell("VirusTotal")
            row.cell(f"Malicious Flags: {vt['malicious'] if vt else 'N/A'}")

            # MetaDefender Row
            meta = data['intel']['metadefender']
            row = table.row()
            row.cell("MetaDefender")
            row.cell("Detected" if meta else "Clean / No Data")

        filename = f"report_{data['domain']}_{datetime.now().strftime('%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        pdf.output(filepath)
        return filepath