import whois
import socket  # NEW: For resolving domains to IPs
from datetime import datetime
from modules.api_clients import APIClient


class PhishScanner:
    def __init__(self):
        self.client = APIClient()
        self.results = {}

    def _get_ip(self, domain):
        """Converts a domain (google.com) into an IP (142.250.x.x)."""
        try:
            return socket.gethostbyname(domain)
        except:
            return None

    def _get_domain_age(self, domain):
        try:
            res = whois.whois(domain)
            created = res.creation_date
            if isinstance(created, list): created = created[0]
            return (datetime.now() - created).days if created else "Unknown"
        except:
            return "Error"

    def scan_email(self, email):
        domain = email.split('@')[-1] if '@' in email else email
        print(f"[*] Researching {domain}...")

        # 1. Resolve IP
        ip_address = self._get_ip(domain)

        # 2. Run all your API tools
        vt_stats = self.client.check_virustotal_domain(domain)
        meta_data = self.client.check_metadefender_domain(domain)
        urlscan_data = self.client.check_urlscan_domain(domain)

        # NEW: Check the IP-based tools
        abuse_data = None
        shodan_data = None
        if ip_address:
            abuse_data = self.client.check_abuse_ip(ip_address)
            shodan_data = self.client.check_shodan_ip(ip_address)

        # 3. Calculate Risk
        age = self._get_domain_age(domain)
        risk_score = 0
        if age != "Unknown" and isinstance(age, int) and age < 30: risk_score += 50
        if vt_stats and vt_stats.get('malicious', 0) > 0: risk_score += 40
        if abuse_data and abuse_data.get('abuseConfidenceScore', 0) > 20: risk_score += 30

        self.results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": email,
            "domain": domain,
            "ip_address": ip_address,
            "domain_age_days": age,
            "risk_score": min(risk_score, 100),
            "intel": {
                "virus_total": vt_stats,
                "metadefender": meta_data,
                "urlscan_recent": urlscan_data,
                "abuse_ip_db": abuse_data,
                "shodan": shodan_data
            }
        }
        return self.results