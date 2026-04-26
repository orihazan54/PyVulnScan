🔍 PyVulnScan
A Python-based network vulnerability scanner that identifies open ports, detects services and versions, and checks for known CVEs against the National Vulnerability Database (NVD).
Built as a learning project to demonstrate networking, multi-threading, API integration, and security fundamentals.

🎯 Features

🚀 Fast Multi-threaded Port Scanning — Scans up to 100 ports concurrently using ThreadPoolExecutor
🔬 Service & Version Detection — Identifies running services through banner grabbing on TCP services and HTTP Server headers
🛡️ CVE Lookup — Queries the official NVD API for known vulnerabilities matching detected service versions
🎨 Rich Terminal Output — Colored, formatted tables using the rich library
📊 HTML Reports — Generates professional HTML reports with summary cards, sortable tables, and severity badges
⚙️ Configurable — Customize timeout, thread count, and CVE lookup behavior via CLI flags


📸 Demo
Terminal Output
╔═══════════════════════════════════════╗
║       PyVulnScan v0.2                 ║
║   Network Vulnerability Scanner       ║
╚═══════════════════════════════════════╝

Phase 1: Port scanning scanme.nmap.org...
[+] Port 22 is OPEN
[+] Port 80 is OPEN
[+] Port 21 is OPEN

Phase 2: Detecting services on 3 open ports...

┌──────┬─────────┬──────────┬─────────────┬────────────────────────────┐
│ Port │ Service │ Product  │ Version     │ Banner                     │
├──────┼─────────┼──────────┼─────────────┼────────────────────────────┤
│  22  │ SSH     │ OpenSSH  │ 6.6.1p1     │ SSH-2.0-OpenSSH_6.6.1p1... │
│  80  │ HTTP    │ Apache   │ 2.4.7       │ Apache/2.4.7 (Ubuntu)      │
│  21  │ FTP     │ ProFTPD  │ 1.3.5       │ 220 ProFTPD 1.3.5 Server   │
└──────┴─────────┴──────────┴─────────────┴────────────────────────────┘
HTML Report
The tool generates a professional HTML report with:

Summary cards showing key statistics
Color-coded severity badges (Critical/High/Medium/Low)
Detailed CVE descriptions
Modern responsive design


🛠️ Tech Stack
ComponentTechnologyLanguagePython 3.8+Networkingsocket (stdlib)Concurrencyconcurrent.futures.ThreadPoolExecutorHTTP ClientrequestsCLIargparseTerminal UIrichHTML TemplatingJinja2Vulnerability DBNVD API 2.0

📦 Installation
Prerequisites

Python 3.8 or higher
pip (Python package manager)
Git

Setup
bash# Clone the repository
git clone https://github.com/orihazan54/PyVulnScan.git
cd PyVulnScan

# Create a virtual environment (recommended)
python -m venv venv

# Activate it
# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

🚀 Usage
Basic Scan
bashpython main.py --target scanme.nmap.org
With Custom Options
bashpython main.py --target 192.168.1.1 --timeout 2.0 --threads 50
Skip CVE Lookup (faster)
bashpython main.py --target scanme.nmap.org --no-cve
CLI Options
FlagDescriptionDefault-t, --targetTarget hostname or IP (required)—--timeoutTimeout per port in seconds1.0--threadsNumber of concurrent threads100--no-cveSkip CVE lookup (faster)False

📂 Project Structure
PyVulnScan/
├── scanner/
│   ├── __init__.py
│   ├── port_scanner.py        # Multi-threaded TCP port scanning
│   ├── service_detector.py    # Banner grabbing & version detection
│   └── cve_checker.py         # NVD API integration
├── reporter/
│   ├── __init__.py
│   ├── html_reporter.py       # HTML report generation
│   └── templates/
│       └── report.html        # Jinja2 HTML template
├── main.py                    # CLI entry point & orchestration
├── requirements.txt           # Python dependencies
├── .gitignore
└── README.md

🧠 How It Works
Phase 1: Port Scanning
The scanner uses TCP socket connections to test if a port is open. Instead of scanning sequentially, it leverages ThreadPoolExecutor to launch multiple connection attempts concurrently, dramatically reducing scan time (from ~13s to ~1s for 20 ports).
Phase 2: Service Detection
For each open port, the tool performs banner grabbing:

Passive grabbing for services that send greetings on connect (SSH, FTP, SMTP)
Active probing for services that require an initial request (HTTP GET)
Regex-based parsing extracts product name and version from banners

Phase 3: CVE Lookup
For services with identified versions, the tool queries the NVD REST API with progressive fallback:

Exact match: "OpenSSH 6.6.1p1"
Major version: "OpenSSH 6.6"
Product only: "OpenSSH"

Results are parsed, sorted by CVSS score (highest first), and severity is mapped:

Critical: 9.0–10.0
High: 7.0–8.9
Medium: 4.0–6.9
Low: 0.1–3.9


🔮 Future Improvements

 UDP port scanning support
 CPE-based CVE matching for higher accuracy
 Async/await refactor with asyncio
 Custom port range input (e.g., --ports 1-1000)
 JSON/CSV export for integration with other tools
 Authentication via NVD API key for higher rate limits
 Docker container for easy deployment
 Unit tests with pytest


⚠️ Disclaimer
This tool is for educational purposes and authorized security testing only.

❌ Do NOT scan networks or hosts without explicit permission
❌ Unauthorized port scanning may violate computer crime laws in your jurisdiction
✅ Use scanme.nmap.org for testing — it is explicitly set up for scanner education
✅ Use only on systems you own or have written authorization to test

The author assumes no responsibility for misuse of this software.

📄 License
MIT License — feel free to use, modify, and share.

👨‍💻 Author
Built by Ori Hazan as a learning project in cybersecurity and software engineering.