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
        """Saves raw analysis data to a JSON file safely."""
        # Use .get() with fallbacks to avoid KeyErrors
        target_name = data.get('domain') or data.get('target', 'unknown_target')
        filename = f"report_{target_name}_{datetime.now().strftime('%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        return filepath

    def save_pdf(self, data):
        """Generates a professional PDF report safely."""
        pdf = FPDF()
        pdf.add_page()

        # Safely extract variables
        target_name = data.get('domain') or data.get('target', 'Unknown')
        timestamp = data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        age = data.get('domain_age_days', 'N/A')
        score = data.get('risk_score', 0)

        # Header
        pdf.set_font("helvetica", "B", 20)
        pdf.cell(0, 10, "PhishLyzer Security Report", ln=True, align="C")
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 10, f"Generated on: {timestamp}", ln=True, align="C")
        pdf.ln(10)

        # Summary Section
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        pdf.set_font("helvetica", "", 12)
        pdf.cell(0, 10, f"Target: {target_name}", ln=True)
        pdf.cell(0, 10, f"Domain Age: {age} days", ln=True)

        # Risk Score with Color Coding
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

        intel = data.get('intel', {})

        with pdf.table() as table:
            row = table.row()
            row.cell("Source")
            row.cell("Finding")

            # VirusTotal Row
            vt = intel.get('virus_total')
            vt_finding = "N/A"
            if isinstance(vt, dict):
                vt_finding = f"Malicious Flags: {vt.get('malicious', 0)}"

            row = table.row()
            row.cell("VirusTotal")
            row.cell(vt_finding)

            # AbuseIPDB Row
            abuse = intel.get('abuse_ip_db')
            abuse_finding = "Clean / No Data"
            if isinstance(abuse, dict):
                conf = abuse.get('abuseConfidenceScore', 0)
                abuse_finding = f"Abuse Confidence: {conf}%"

            row = table.row()
            row.cell("AbuseIPDB")
            row.cell(abuse_finding)

        filename = f"report_{target_name}_{datetime.now().strftime('%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        pdf.output(filepath)
        return filepath