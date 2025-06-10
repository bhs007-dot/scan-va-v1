# Automated Vulnerability Assessment & Exploitation Script

Donate for me over crypto BTC ADDRESS 
12zsQF6XgiNtu5SgGUgi5R66DwhTyPTSaN


![Banner](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-IT%20Solutions%20007-green)

## Overview

**File:** `SCAN-VA-v5.py`

This tool is an **automated vulnerability assessment and exploitation framework** for penetration testers and security professionals. It integrates Nmap, Dalfox, Nuclei, SQLmap, and Metasploit to provide a streamlined workflow for scanning, identifying, and exploiting vulnerabilities, as well as generating professional PDF reports.

**Author:** IT Solutions 007  
**Instagram:** [@itsolutions007](https://instagram.com/itsolutions007)

---

## Features

- **Nmap Integration:**  
  - Quick, service/version, OS, and full port scans
  - Vulnerability detection with CVE extraction

- **Web Vulnerability Scanning:**  
  - Dalfox for XSS
  - Nuclei for web vulnerabilities
  - SQLmap for SQL injection

- **Metasploit Automation:**  
  - Maps detected CVEs to Metasploit modules
  - Launches exploitation modules in a new terminal

- **Network Traffic Analysis:**  
  - Automated capture and analysis using tshark/Wireshark

- **PDF Reporting:**  
  - Generates a comprehensive PDF report of findings

- **User-Friendly Menu:**  
  - Interactive CLI for all features

---

## Requirements

- **Python 3.8+**
- [Nmap](https://nmap.org/)
- [Dalfox](https://github.com/hahwul/dalfox)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [SQLmap](https://github.com/sqlmapproject/sqlmap)
- [Metasploit Framework](https://www.metasploit.com/)
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- Python packages: `requests`, `fpdf`, `qrcode`

Install Python dependencies:
```bash
pip install requests fpdf qrcode
git clone https://github.com/bhs007-dot/SCAN-VA-v5.git
cd SCAN-VA-v5
python3 SCAN-VA-v5.py
Follow the interactive menu to perform scans, exploit vulnerabilities, and generate reports.

Example Workflow
Select "Full Vulnerability Assessment & Report & Exploitation" from the main menu.
Choose your target and scan options.
Review detected CVEs and exploit with Metasploit if desired.
Run web vulnerability scans (Dalfox, Nuclei, SQLmap).
Generate and review the PDF report.
Legal Disclaimer
This tool is intended only for authorized penetration testing and security assessment.

You must have explicit permission to scan and test the target systems.

The author is not responsible for any misuse or damage caused by this tool.

Credits
Developed by IT Solutions 007
Instagram: @itsolutions007
