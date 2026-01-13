import os
import requests
from dotenv import load_dotenv

# Load keys from the .env file
load_dotenv()

class APIClient:
    def __init__(self):
        self.vt_key = os.getenv("VT_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        self.urlscan_key = os.getenv("URLSCAN_API_KEY")
        self.meta_key = os.getenv("METADEFENDER_API_KEY")

    def check_abuse_ip(self, ip_address):
        """Checks if an IP is reported for malicious activity on AbuseIPDB."""
        if not self.abuse_key: return None
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        try:
            response = requests.get(url, headers=headers, params=params)
            return response.json()['data'] if response.status_code == 200 else None
        except Exception:
            return None

    def check_virustotal_domain(self, domain):
        """Checks a domain's reputation on VirusTotal."""
        if not self.vt_key: return None
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.vt_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                # Returns the analysis stats (malicious, harmless, etc.)
                return response.json()['data']['attributes']['last_analysis_stats']
            return None
        except Exception:
            return None

    def check_shodan_ip(self, ip_address):
        """Uses Shodan to see ports/services open on an IP."""
        if not self.shodan_key: return None
        url = f"https://api.shodan.io/shodan/host/{ip_address}?key={self.shodan_key}"
        try:
            response = requests.get(url)
            return response.json() if response.status_code == 200 else None
        except Exception:
            return None

    def check_metadefender_domain(self, domain):
        """Checks domain reputation via MetaDefender Cloud."""
        if not self.meta_key: return None
        url = f"https://api.metadefender.com/v4/domain/{domain}"
        headers = {"apikey": self.meta_key}
        try:
            response = requests.get(url, headers=headers)
            return response.json() if response.status_code == 200 else None
        except Exception:
            return None

    def check_urlscan_domain(self, domain):
        """Searches URLScan.io for recent scans of this domain."""
        if not self.urlscan_key: return None
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        headers = {"API-Key": self.urlscan_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json().get('results', [])[:3]
            return None
        except Exception:
            return None