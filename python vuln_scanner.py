import socket
import sys
from datetime import datetime


VULNERABLE_VERSIONS = {
    "SSH-1.99-OpenSSH_miniproject": "Critical: Outdated SSH protocol version (SSHv1 is insecure).",
    "Apache/2.4.41": "Medium: Outdated Apache version. Consider upgrading to the latest release.",
    "vsftpd 2.3.4": "High: Known backdoor vulnerability exists in this specific version."
}

class MiniVulnerabilityScanner:
    def __init__(self, target_host="127.0.0.1"):
        self.target_host = target_host
        self.target_ports = [21, 22, 80, 443]

    def scan_ports(self):
        print("-" * 50)
        print(f"Scanning Target: {self.target_host}")
        print(f"Time Started: {str(datetime.now())}")
        print("-" * 50)
        
        report = []

        try:
            for port in self.target_ports:
               
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              
                s.settimeout(1.0)
                
                result = s.connect_ex((self.target_host, port))
                
                if result == 0:
                    port_info = f"[+] Port {port} is OPEN"
                    print(port_info)
                    
                   
                    banner = self._grab_banner(s)
                    vulnerability_notes = ""
                    
                    if banner:
                        print(f"    -> Banner Detected: {banner}")
                        vulnerability_notes = self._check_vulnerabilities(banner)
                        if vulnerability_notes:
                            print(f"    [!] Vulnerability Alert: {vulnerability_notes}")
                    
                    report.append({
                        "port": port,
                        "status": "Open",
                        "banner": banner if banner else "Unknown",
                        "vulnerability": vulnerability_notes if vulnerability_notes else "None Detected (Basic Check)"
                    })
                s.close()
                
        except socket.gaierror:
            print("\n[!] Hostname could not be resolved.")
        except socket.error:
            print("\n[!] Could not connect to the server.")
            
        return report

    def _grab_banner(self, s):
        """Attempts to read the initial welcome message (banner) from the service."""
        try:
        
            return s.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            return None

    def _check_vulnerabilities(self, banner):
        """Compares the detected banner against our mock database of outdated software."""
        for vuln_version, description in VULNERABLE_VERSIONS.items():
            if vuln_version in banner:
                return description
        return None

    def generate_report(self, scan_results):
        """Generates a simple text-based vulnerability report summary."""
        print("\n" + "="*20 + " VULNERABILITY REPORT " + "="*20)
        if not scan_results:
            print("No open ports or services were detected.")
            return

        for result in scan_results:
            print(f"\n• Port {result['port']} ({result['status']})")
            print(f"  Service Banner: {result['banner']}")
            print(f"  Security Status: {result['vulnerability']}")
        print("=" * 62)

if __name__ == "__main__":
    scanner = MiniVulnerabilityScanner("127.0.0.1")
    results = scanner.scan_ports()
    scanner.generate_report(results)