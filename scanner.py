import socket
import argparse
import threading
import re
import requests
import time
import json
from queue import Queue

# Threading locks
print_lock = threading.Lock()
list_lock = threading.Lock()

# Common weak services mapping
WEAK_SERVICES = {
    21: "FTP (File Transfer Protocol) - Data is sent in plaintext.",
    23: "Telnet - Completely unencrypted communication.",
    80: "HTTP - Web traffic without SSL/TLS encryption.",
    110: "POP3 - Unencrypted email retrieval.",
    143: "IMAP - Unencrypted email retrieval.",
    3306: "MySQL - Unencrypted database connection (if SSL not forced).",
}

# The top ~100 ports to scan for a fast scan
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

def scan_port(target, port, open_ports, timeout=1.0, debug=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            with list_lock:
                open_ports.append(port)
            with print_lock:
                print(f"[+] Port {port} is OPEN")
        s.close()
    except Exception as e:
        if debug:
            with print_lock:
                print(f"[DEBUG] Port {port} scan exception: {e}")

def get_service_name(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return "unknown"

def grab_banner(target, port, timeout=2.0, debug=False):
    banner = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        
        # Give some services time to send the initial banner
        if port in [80, 443, 8080, 8443]:
            # Send dummy HTTP request
            request = b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
            s.send(request)
        
        data = s.recv(1024)
        if data:
            banner = data.decode('utf-8', errors='ignore').strip()
        s.close()
    except Exception as e:
        if debug:
            with print_lock:
                print(f"[DEBUG] Port {port} banner grab error: {e}")
    return banner

def analyze_weakness(port):
    if port in WEAK_SERVICES:
        return WEAK_SERVICES[port]
    return None

def extract_software_info(banner):
    """
    Attempt to extract software name and version from a banner using heuristics/regex.
    """
    info = {
        "software": None,
        "version": None,
        "cpe_hint": None
    }
    
    if not banner:
        return info

    # Check for SSH
    ssh_match = re.search(r'SSH-[\d\.]+-([^\s]+)', banner, re.IGNORECASE)
    if ssh_match:
        full_sw = ssh_match.group(1)
        parts = full_sw.split('_')
        if len(parts) >= 2:
            info['software'] = parts[0]
            info['version'] = parts[1]
            if "openssh" in info['software'].lower():
                info['cpe_hint'] = f"cpe:2.3:a:openbsd:openssh:{info['version']}:*:*:*:*:*:*:*"
        else:
            info['software'] = full_sw
        return info

    # Check for HTTP Server header
    server_match = re.search(r'Server:\s*([a-zA-Z\-]+)/([\d\.]+)', banner, re.IGNORECASE)
    if server_match:
        info['software'] = server_match.group(1)
        info['version'] = server_match.group(2)
        if "apache" in info['software'].lower():
            info['cpe_hint'] = f"cpe:2.3:a:apache:http_server:{info['version']}:*:*:*:*:*:*:*"
        elif "nginx" in info['software'].lower():
            info['cpe_hint'] = f"cpe:2.3:a:f5:nginx:{info['version']}:*:*:*:*:*:*:*"
        return info

    # Check for generic FTP
    ftp_match = re.search(r'220[\-\s]+.*?\b([a-zA-Z]+)[\s\-]+([\d\.]+)', banner)
    if ftp_match:
        info['software'] = ftp_match.group(1)
        info['version'] = ftp_match.group(2)
        return info

    return info

def lookup_cves(software, version, cpe_hint=None, debug=False):
    """
    Queries the NIST NVD API for known vulnerabilities.
    Prioritizes CPE matching if a hint is available, falls back to keyword matching.
    """
    print(f"[*] Looking up CVEs for {software} {version}...")
    
    # NVD API v2 Endpoint
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # If we mapped a CPE, try a more exact match using virtualMatchString
    if cpe_hint:
        url = f"{base_url}?virtualMatchString={requests.utils.quote(cpe_hint)}&resultsPerPage=5"
    else:
        keyword = f"{software} {version}"
        url = f"{base_url}?keywordSearch={requests.utils.quote(keyword)}&resultsPerPage=5"
    
    try:
        headers = {
            'User-Agent': 'Python Vuln Scanner Demo/2.0'
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            cves = []
            results = data.get('vulnerabilities', [])
            for item in results:
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id')
                description = ""
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value')
                        break
                
                # Check CVSS Score
                cvss_metrics = cve_data.get('metrics', {})
                score = "Unknown"
                if 'cvssMetricV31' in cvss_metrics:
                    score = cvss_metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                elif 'cvssMetricV30' in cvss_metrics:
                    score = cvss_metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                elif 'cvssMetricV2' in cvss_metrics:
                    score = cvss_metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                
                cves.append({
                    "id": cve_id,
                    "score": score,
                    "description": description[:100] + "..." if len(description) > 100 else description
                })
            return cves
        elif response.status_code in [403, 503]:
            # Provide more info if blocked
            print(f"[!] Rate limited or blocked by NVD API. Try again later.")
            if debug:
                print(f"[DEBUG] API Status: {response.status_code}, Body: {response.text[:200]}")
        else:
            print(f"[!] Error looking up CVEs: API returned {response.status_code}")
            
    except Exception as e:
        if debug:
            print(f"[DEBUG] Error making CVE request: {e}")
        else:
            print(f"[!] Error making CVE request. Enable --debug for details.")
    
    return []

def worker(target, port_queue, open_ports, timeout, debug):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port, open_ports, timeout, debug)
        port_queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="Python Vulnerability Scanner (Port Scan, Banner Grab, CVEs)")
    parser.add_argument("target", help="Target IP address or hostname to scan")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-p", "--ports", help="Comma-separated ports to scan (e.g., 22,80,443) or 'all' for 1-65535. Default: top ports")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket connect timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", help="Save scan results to a JSON report file (e.g., report.json)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output for exceptions")
    args = parser.parse_args()

    target = args.target
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"[!] Complete failure resolving hostname: {target}")
        if args.debug:
            print(f"[DEBUG] {e}")
        return

    print(f"[*] Starting scan on {target} ({target_ip})")
    print(f"[*] Threads: {args.threads}")

    port_list = TOP_PORTS
    if args.ports:
        if args.ports.lower() == 'all':
            port_list = range(1, 65536)
        else:
            try:
                port_list = [int(p.strip()) for p in args.ports.split(",")]
            except ValueError:
                print("[!] Invalid port list format.")
                return

    open_ports = []
    port_queue = Queue()

    for p in port_list:
        port_queue.put(p)

    threads_list = []
    for _ in range(args.threads):
        thread = threading.Thread(target=worker, args=(target_ip, port_queue, open_ports, args.timeout, args.debug))
        threads_list.append(thread)
        thread.start()

    for thread in threads_list:
        thread.join()

    open_ports.sort()
    
    print("\n" + "="*50)
    print("SCAN RESULTS")
    print("="*50)
    
    if not open_ports:
        print("No open ports found.")
        return

    scan_report = {
        "target": target,
        "target_ip": target_ip,
        "open_ports": {}
    }

    for port in open_ports:
        print(f"\n[PORT {port}]")
        
        # New Feature: Service Mapping
        service_name = get_service_name(port)
        print(f"  [*] Detected Service via IANA: {service_name.upper()}")
        
        # 1. Weak service check
        weakness = analyze_weakness(port)
        if weakness:
            print(f"  [!] WARNING Weak Service: {weakness}")
        else:
            print(f"  [-] Service protocol considered standard.")
            
        # 2. Banner Grabbing
        print(f"  [*] Grabbing banner...")
        banner = grab_banner(target_ip, port, timeout=args.timeout, debug=args.debug)
        
        sw_software = None
        sw_version = None
        cves_found = []

        if banner:
            display_banner = banner.replace('\\r\\n', ' ').replace('\\n', ' ').replace('\\r', '')
            if len(display_banner) > 80:
                display_banner = display_banner[:77] + "..."
            print(f"  [+] Banner: {display_banner}")
            
            # 3. Detect software/version
            sw_info = extract_software_info(banner)
            if sw_info['software'] and sw_info['version']:
                sw_software = sw_info['software']
                sw_version = sw_info['version']
                print(f"  [+] Identified Software: {sw_software} | Version: {sw_version}")
                
                # 4. CVE Lookup (improved with CPE hints)
                cves_found = lookup_cves(sw_software, sw_version, sw_info.get('cpe_hint'), debug=args.debug)
                if cves_found:
                    print(f"  [!] Found {len(cves_found)} recent vulnerabilities:")
                    for cve in cves_found:
                        print(f"      - {cve['id']} (CVSS: {cve['score']}): {cve['description']}")
                else:
                    print(f"  [-] No specific CVEs found (or API limit reached).")
                
                # Be gentle to NVD API
                time.sleep(1)
            else:
                print("  [-] Could not confidently identify software/version from banner.")
        else:
            print("  [-] No banner received.")

        # Save port findings to report
        scan_report["open_ports"][port] = {
            "mapped_service": service_name,
            "weakness_warning": weakness,
            "banner": banner,
            "identified_software": sw_software,
            "identified_version": sw_version,
            "vulnerabilities": cves_found
        }

    print("\n[*] Scan complete.")

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(scan_report, f, indent=4)
            print(f"[*] Detailed JSON report saved to: {args.output}")
        except Exception as e:
            print(f"[!] Warning: Failed to save JSON report to {args.output}")
            if args.debug:
                print(f"[DEBUG] JSON save error: {e}")

if __name__ == "__main__":
    main()
