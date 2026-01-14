import whois
import socket
import ipaddress
import json
import os
from datetime import datetime
from modules.api_clients import APIClient


class PhishScanner:
    def __init__(self):
        self.client = APIClient()
        self.results = {}

    def _get_ip(self, domain):
        try:
            return socket.gethostbyname(domain)
        except:
            return None

    def _get_domain_age(self, domain):
        """Safely get domain age and return as an integer or 'Unknown'."""
        try:
            res = whois.whois(domain)
            if not isinstance(res, dict):
                created = getattr(res, 'creation_date', None)
            else:
                created = res.get('creation_date')

            if isinstance(created, list):
                created = created[0]

            if created and isinstance(created, datetime):
                return (datetime.now() - created).days
            return "Unknown"
        except Exception as e:
            # Captures WHOIS lookup errors (like "No match") as N/A
            print(f"[!] WHOIS lookup skipped: {e}")
            return "N/A"

    def _calculate_risk(self, vt_malicious, abuse_conf, age):
        """
        High-Sensitivity scoring algorithm.
        Ensures that 'Unknown' or 'New' domains are flagged even if APIs are clean.
        """
        score = 0

        # 1. VirusTotal Penalty (Reactive Detection)
        # If even one engine flags it, we start at 40 points.
        if vt_malicious > 0:
            score += 40 + (vt_malicious * 10)

        # 2. AbuseIPDB Penalty (Reactive Detection)
        if abuse_conf > 25:
            score += (abuse_conf / 2)

        # 3. Domain Age & "Unknown" Penalty (Proactive Detection)
        # This is where we catch "Zero-Day" phishing.
        if age in ["Unknown", "N/A", None]:
            # If we can't verify the age, it's a suspicious 'grey' area.
            score += 35
        elif isinstance(age, (int, float)):
            if age < 30:
                score += 60  # Extremely high risk: Domain registered < 1 month ago
            elif age < 365:
                score += 25  # Moderate risk: Domain is less than a year old

        # Final score is capped at 100
        return int(min(score, 100))

    def scan_email(self, email):
        # Clean input
        target = email.split('@')[-1] if '@' in email else email
        print(f"\n[*] Researching: {target}")

        self.results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": email,
            "ip_address": "Not Resolved",
            "domain_age_days": "N/A",
            "risk_score": 0,
            "intel": {
                "virus_total": {"malicious": 0},
                "abuse_ip_db": {"abuseConfidenceScore": 0}
            }
        }

        try:
            # 1. Detect if target is an IP or Domain
            is_ip = False
            try:
                ipaddress.ip_address(target)
                is_ip = True
                ip_address = target
            except ValueError:
                ip_address = self._get_ip(target)

            self.results["ip_address"] = ip_address or "Not Resolved"

            # 2. Intel Gathering
            print("[*] Querying Intelligence APIs...")
            if is_ip:
                vt_stats = self.client.check_virustotal_ip(target)
            else:
                vt_stats = self.client.check_virustotal_domain(target)

            abuse_data = self.client.check_abuse_ip(ip_address) if ip_address else None
            age = self._get_domain_age(target) if not is_ip else "N/A"

            # 3. Defensive Update of Results
            self.results["domain_age_days"] = age
            if vt_stats: self.results["intel"]["virus_total"] = vt_stats
            if abuse_data: self.results["intel"]["abuse_ip_db"] = abuse_data

            # 4. Final Scoring
            vt_malicious = self.results["intel"]["virus_total"].get('malicious', 0)
            abuse_conf = self.results["intel"]["abuse_ip_db"].get('abuseConfidenceScore', 0)

            # Assign the calculated risk to results
            self.results["risk_score"] = self._calculate_risk(vt_malicious, abuse_conf, age)

        except Exception as global_err:
            print(f"[X] Analysis partially completed due to: {global_err}")

        return self.results