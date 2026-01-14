# PhishLyzer 🛡️

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/OSINT-Tool-red)

PhishLyzer is a robust, Python-based **Open Source Intelligence (OSINT)** tool designed to help security professionals, SOC analysts, and investigators verify the legitimacy of email senders and network infrastructure.

By correlating data from multiple live threat intelligence sources, PhishLyzer provides a comprehensive view of a domain or IP's reputation—summarized in a professional, actionable PDF report.

## ✨ Key Features
- **Smart Target Detection:** Automatically distinguishes between email domains and direct IP addresses.
- **Multi-Source Intelligence:** Real-time integration with **VirusTotal** and **AbuseIPDB**.
- **Historical Analysis:** Performs WHOIS lookups to calculate domain age and identify "throwaway" infrastructure.
- **Dynamic Risk Scoring:** A weighted 0-100 algorithm considering age, blacklist hits, and confidence scores.
- **Resilient Logic:** Bulletproof error handling ensures reports are generated even if individual APIs or WHOIS lookups fail.
- **Professional Reporting:** Generates color-coded **PDF** and **JSON** reports for every scan.

## 🚀 Setup Instructions

### 1. Installation
```bash
git clone https://github.com/yourusername/PhishLyzer.git
cd PhishLyzer
pip install -r requirements.txt

2. Configuration
Rename the .env.example file to .env and add your API keys:

VirusTotal API: Get it here

AbuseIPDB API: Get it here

3. Usage
Run the tool directly using Python:

Bash

python main.py
🛠️ Build for Windows (.exe)
To build a standalone executable including the required WHOIS data dependencies, use:
pyinstaller --clean --onefile --name PhishLyzer --add-data "modules;modules" --add-data ".venv/Lib/site-packages/whois/data/public_suffix_list.dat;whois/data" main.py

Sample Output
Target: admin@141.98.11.11

Risk Score: 90/100 (DANGER)

Intelligence Summary: 14 VirusTotal Malicious Flags, 100% Abuse Confidence Score.

⚠️ Disclaimer
This tool is for educational and ethical security research purposes only. The author is not responsible for any misuse of this tool. Always ensure you have explicit permission before scanning infrastructure or interacting with suspicious entities.

Developed as a modular, resilient OSINT solution.
---

### 🎨 Why this version is better:
* **Closed Code Blocks:** I added the ` ``` ` at the end of the installation, usage, and build sections. Without these, the "Sample Output" and "Disclaimer" would look like code text instead of headers.
* **Clean Links:** Simplified the GitHub clone link so it doesn't show the full URL twice.

### 🏁 Final Steps:
1.  **requirements.txt**: Open your terminal, go to your project folder, and run:
    `pip freeze > requirements.txt`
2.  **LICENSE**: Go to your GitHub repo online, click **Add file > Create new file**, name it `LICENSE`, and choose the **MIT License** template.
3.  **Push**: Run `git add .`, then `git commit -m "Complete PhishLyzer v1.0"`, then `git push`.



**You are 100% ready. Would you like to do a final check of the `requirements.txt` content before you push?**

