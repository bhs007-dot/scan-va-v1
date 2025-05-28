Automated Vulnerability Assessment & Exploitation Script
Banner License

Overview
This tool is an automated vulnerability assessment and exploitation framework for penetration testers and security professionals. It integrates Nmap, Dalfox, Nuclei, SQLmap, and Metasploit to provide a streamlined workflow for scanning, identifying, and exploiting vulnerabilities, as well as generating professional PDF reports.

Author: IT Solutions 007

Instagram: @itsolutions007

Features
Nmap Integration:

Quick, service/version, OS, and full port scans
Vulnerability detection with CVE extraction
Web Vulnerability Scanning:

Dalfox for XSS
Nuclei for web vulnerabilities
SQLmap for SQL injection
Metasploit Automation:

Maps detected CVEs to Metasploit modules
Launches exploitation modules in a new terminal
Network Traffic Analysis:

Automated capture and analysis using tshark/Wireshark
PDF Reporting:

Generates a comprehensive PDF report of findings
User-Friendly Menu:

Interactive CLI for all features
Requirements
Python 3.8+
Nmap
Dalfox
Nuclei
SQLmap
Metasploit Framework
tshark
Python packages: requests, fpdf, qrcode
Install Python dependencies:

bash

Copy
pip install requests fpdf qrcode
Usage
Clone the repository:

bash

Copy
git clone https://github.com/yourusername/yourrepo.git
cd yourrepo
Run the script:

bash

Copy
python3 yourscript.py
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
