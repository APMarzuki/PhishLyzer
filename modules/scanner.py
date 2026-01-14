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
        """Safely get domain age without crashing on KeyError."""
        try:
            res = whois.whois(domain)

            # Use .get() on the dictionary to avoid KeyError: 'domain'
            if not isinstance(res, dict):
                # If whois returns a custom object, we safely convert it
                created = getattr(res, 'creation_date', None)
            else:
                created = res.get('creation_date')

            if isinstance(created, list):
                created = created[0]

            if created and isinstance(created, datetime):
                return (datetime.now() - created).days
            return "Unknown"
        except Exception as e:
            # This catches the [Errno 2] missing file error without crashing the app
            print(f"[!] WHOIS lookup skipped: {e}")
            return "N/A"

    def scan_email(self, email):
        # Clean input: get the part after @ or use the whole thing if it's an IP
        target = email.split('@')[-1] if '@' in email else email
        print(f"\n[*] Researching: {target}")

        # Initialize results immediately so we have a 'safety net'
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

            # 4. Scoring Logic (Using .get to prevent crashes)
            score = 0

            # VirusTotal Score
            vt_malicious = self.results["intel"]["virus_total"].get('malicious', 0)
            if vt_malicious > 0: score += 50

            # AbuseIPDB Score
            abuse_conf = self.results["intel"]["abuse_ip_db"].get('abuseConfidenceScore', 0)
            if abuse_conf > 25: score += 40

            # Age Score
            if isinstance(age, int) and age < 30: score += 30

            self.results["risk_score"] = min(score, 100)

        except Exception as global_err:
            print(f"[X] Analysis partially completed due to: {global_err}")

        return self.results