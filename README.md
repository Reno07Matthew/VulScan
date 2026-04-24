# VulScan 🛡️

A powerful, multi-threaded Python-based vulnerability scanner with a premium web-based dashboard for discovery and assessment.

## 🚀 Features

- **Modern Web Dashboard**: A sleek, dark-themed "Glassmorphism" UI for easy scanning and result visualization.
- **Multi-threaded Port Scanning**: Rapidly scans target hosts for open ports.
- **Service Mapping**: Automatically maps port numbers to standard IANA service names.
- **Banner Grabbing**: Intercepts initial service headers to identify running software.
- **Intelligent Software Detection**: Uses regex heuristics to extract software names and versions.
- **CVE Integration**: Queries the NIST National Vulnerability Database (NVD) using **CPE 2.3** matching for highly accurate vulnerability reporting.
- **Weak Service Alerts**: Flags unencrypted protocols like HTTP, Telnet, and FTP.
- **JSON Output**: Save detailed scan results to a structured JSON file.
- **Debug Mode**: Detailed error logging to troubleshoot connection issues.

## 🛠️ Installation & Requirements

### Prerequisites
- Python 3.x

### Setup
1. Clone the repository and navigate into it.
2. Create a virtual environment and install dependencies:
```bash
python -m venv venv
./venv/bin/pip install flask flask-cors requests
```

## 📖 Usage

### 🌐 Web Interface (Recommended)
Start the web dashboard:
```bash
./venv/bin/python app.py
```
Then visit **`http://127.0.0.1:5000`** in your browser.

### 💻 CLI Mode
Scan a host using the top common ports:
```bash
python3 scanner.py <target_ip_or_hostname>
```

#### Advanced CLI usage:
```bash
python3 scanner.py scanme.nmap.org -p 22,80,443 -t 10 -o report.json
```

## ⚠️ Disclaimer

**This tool is for educational and authorized security testing purposes only.** 
Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for any misuse or damage caused by this tool.

## 📄 License

This project is open-source. Feel free to use and modify it.
