import os
import requests
from dotenv import load_dotenv

load_dotenv()

class APIClient:
    def __init__(self):
        self.vt_key = os.getenv("VT_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    def _parse_vt_stats(self, data):
        """Safely extract stats without triggering KeyErrors."""
        try:
            # We use .get() at every level to prevent crashes
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            return {
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "undetected": stats.get('undetected', 0)
            }
        except Exception:
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}

    def check_virustotal_domain(self, domain):
        if not self.vt_key: return None
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.vt_key}
        try:
            response = requests.get(url, headers=headers)
            return self._parse_vt_stats(response.json()) if response.status_code == 200 else None
        except: return None

    def check_virustotal_ip(self, ip_address):
        if not self.vt_key: return None
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.vt_key}
        try:
            response = requests.get(url, headers=headers)
            return self._parse_vt_stats(response.json()) if response.status_code == 200 else None
        except: return None

    def check_abuse_ip(self, ip_address):
        if not self.abuse_key: return None
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        try:
            response = requests.get(url, headers=headers, params=params)
            # Use .get('data') to avoid KeyError if 'data' is missing
            return response.json().get('data') if response.status_code == 200 else None
        except: return None