# VulScan 

A multi-threaded Python-based vulnerability scanner designed for fast discovery and assessment.

##  Features

- **Multi-threaded Port Scanning**: Rapidly scans target hosts for open ports.
- **Service Mapping**: Automatically maps port numbers to standard IANA service names.
- **Banner Grabbing**: Intercepts initial service headers to identify running software.
- **Intelligent Software Detection**: Uses regex heuristics to extract software names and versions.
- **CVE Integration**: Queries the NIST National Vulnerability Database (NVD) using **CPE 2.3** matching for highly accurate vulnerability reporting.
- **Weak Service Alerts**: Flags unencrypted protocols like HTTP, Telnet, and FTP.
- **JSON Output**: Save detailed scan results to a structured JSON file for further analysis.
- **Debug Mode**: Detailed error logging to troubleshoot connection issues.

##  Disclaimer

**This tool is for educational and authorized security testing purposes only.** 
Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for any misuse or damage caused by this tool.

##  License

This project is open-source. Feel free to use and modify it.
