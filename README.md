# Network Socket Vulnerability & Port Scanner

A lightweight, high-performance network security audit tool built from scratch using Python's native socket interface. This project simulates tactical reconnaissance operations by performing network port scanning, service banner grabbing, and rule-based vulnerability assessment against known outdated software threats.

## 🌟 Security & Analytical Features

- **Multi-Port Reconnaissance:** Scans vital infrastructure transport layers (FTP, SSH, HTTP, HTTPS) using low-overhead TCP handshake verification (`socket.connect_ex`).
- **Dynamic Service Banner Grabbing:** Implements an asynchronous buffer readout mechanism to intercept greeting signatures (banners) broadcasted by active remote or local services.
- **Rule-Based Vulnerability Detection:** Evaluates captured network banners against a static vulnerability cross-reference map (`VULNERABLE_VERSIONS`), flagging critical threats like legacy SSH parameters or known backdoored system versions (e.g., *vsftpd 2.3.4*).
- **Graceful Network Exception Handling:** Defensive code architecture designed to isolate and catch runtime network failures, hostname resolution deadlocks (`socket.gaierror`), and connection timeouts without breaking the pipeline.
- **Automated Security Reporting:** Compiles network evaluation metrics into a standardized, human-readable text audit log mapping ports, detection status, and threat classifications.

## 🛠️ Cyber Security Tech Stack

- **Core Engine:** Python 3.x
- **Network Interface Layer:** Native `socket` module (Dependency-Free / Raw Socket API)
- **Log Management:** Native `sys` and `datetime` components

## 📁 Repository Structure

```text
vuln-scanner/
├── vuln_scanner.py        # Core Python implementation (Socket Logic & Database)
└── README.md              # Granular deployment & vulnerability reference guide
🚀 Deployment & Usage
​Installation
​This architecture is entirely dependency-free, utilizing Python’s built-in networking subsystem. No external pip libraries are required.
​Running the Vulnerability Scanner
​To launch the automated scanner against your designated infrastructure sandbox interface (default target set to loopback 127.0.0.1), execute the script via your terminal:

python vuln_scanner.py

📊 Operational Architecture Flow
​Initialization: The socket engine binds to the target host and defines target port targets (21, 22, 80, 443).
​Probing Layer: A TCP connection sequence is triggered with an enforced 1.0 second timeout threshold to filter out hanging handshakes.
​Banner Extraction: If a port returns a successful connection code (0), the scanner intercepts the welcome packet data stream.
​Signature Matching: The system parses the tokenized string to look for pattern anomalies or outdated software identifiers.
​Reporting: A clean terminal matrix compiles the security posture:
​Example Trigger: Capturing an outdated server instance returns a prompt warning label: [!] Vulnerability Alert: High: Known backdoor vulnerability exists...
​🛡️ Strategic Application & Disclaimer
​This script is designed for educational security research, local infrastructure auditing, and portfolio evaluation for cyber security programs (such as the Global Korea Scholarship). It models defensive security auditing workflows used by systems administrators to monitor active open assets within an enterprise boundary. Always ensure explicit authorization before scanning remote production networks.
