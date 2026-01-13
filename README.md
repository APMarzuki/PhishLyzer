# PhishLyzer 🛡️

PhishLyzer is a Python-based Open Source Intelligence (OSINT) tool designed to help security professionals and investigators verify the legitimacy of email senders. 

By correlating data from multiple threat intelligence sources, PhishLyzer provides a comprehensive view of a domain's reputation, infrastructure, and potential risk—summarized in a professional PDF report.

## Features
- **Domain Age Analysis:** Identifies fresh "throwaway" domains.
- **Multi-API Intelligence:** Integrated with VirusTotal, MetaDefender, AbuseIPDB, Shodan, and URLScan.
- **Risk Scoring:** Automated risk calculation (0-100).
- **Professional Reporting:** Generates PDF and JSON reports for every scan.

## Setup Instructions

### 1. Installation
Ensure you have Python 3.x installed, then install the dependencies:
```bash
pip install -r requirements.txt