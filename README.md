# VulScan 🛡️

A powerful, multi-threaded Python-based vulnerability scanner designed for fast discovery and assessment.

## 🚀 Features

- **Multi-threaded Port Scanning**: Rapidly scans target hosts for open ports.
- **Service Mapping**: Automatically maps port numbers to standard IANA service names.
- **Banner Grabbing**: Intercepts initial service headers to identify running software.
- **Intelligent Software Detection**: Uses regex heuristics to extract software names and versions.
- **CVE Integration**: Queries the NIST National Vulnerability Database (NVD) using **CPE 2.3** matching for highly accurate vulnerability reporting.
- **Weak Service Alerts**: Flags unencrypted protocols like HTTP, Telnet, and FTP.
- **JSON Output**: Save detailed scan results to a structured JSON file for further analysis.
- **Debug Mode**: Detailed error logging to troubleshoot connection issues.

## 🛠️ Requirements

- Python 3.x
- `requests` library

```bash
pip install requests
```

## 📖 Usage

### Basic Scan
Scan a host using the top common ports:
```bash
python3 scanner.py <target_ip_or_hostname>
```

### Advanced Scan
Scan specific ports with multiple threads and save the output:
```bash
python3 scanner.py scanme.nmap.org -p 22,80,443 -t 10 -o report.json
```

### Full Range Scan
```bash
python3 scanner.py 127.0.0.1 -p all --debug
```

## 📊 Sample Output

```text
[*] Starting scan on scanme.nmap.org (45.33.32.156)
[*] Threads: 5
[+] Port 80 is OPEN

[PORT 80]
  [*] Detected Service via IANA: HTTP
  [!] WARNING Weak Service: HTTP - Web traffic without SSL/TLS encryption.
  [*] Grabbing banner...
  [+] Banner: HTTP/1.1 200 OK ... Server: Apache/2.4.7
  [+] Identified Software: Apache | Version: 2.4.7
[*] Looking up CVEs for Apache 2.4.7...
  [!] Found 5 recent vulnerabilities:
      - CVE-2021-44224 (CVSS: 8.2): A crafted URI sent to httpd configured as a forward proxy...
```

## ⚠️ Disclaimer

**This tool is for educational and authorized security testing purposes only.** 
Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for any misuse or damage caused by this tool.

## 📄 License

This project is open-source. Feel free to use and modify it.
