# Port exposure multipliers — higher means more exposed/dangerous
PORT_EXPOSURE = {
    21: 1.5,    # FTP
    22: 1.0,    # SSH (standard, but still exposed)
    23: 2.0,    # Telnet (very dangerous)
    25: 1.2,    # SMTP
    53: 1.0,    # DNS
    80: 1.3,    # HTTP
    110: 1.4,   # POP3
    111: 1.5,   # RPCbind
    135: 1.6,   # MSRPC
    139: 1.7,   # NetBIOS
    143: 1.4,   # IMAP
    161: 1.8,   # SNMP
    443: 0.8,   # HTTPS (encrypted, lower risk)
    445: 1.8,   # SMB
    993: 0.8,   # IMAPS
    995: 0.8,   # POP3S
    1723: 1.3,  # PPTP
    3306: 1.7,  # MySQL
    3389: 1.9,  # RDP
    5900: 1.8,  # VNC
    6379: 1.8,  # Redis
    8080: 1.3,  # HTTP-Alt
    8443: 0.9,  # HTTPS-Alt
    27017: 1.7, # MongoDB
}

# Remediation database for common services
REMEDIATION_DB = {
    "ftp": {
        "service": "FTP",
        "risk_summary": "FTP transmits data including credentials in plaintext.",
        "steps": [
            "Disable FTP and switch to SFTP or SCP",
            "If FTP is required, enforce FTPS (FTP over TLS)"
        ],
        "commands": [
            "sudo systemctl stop vsftpd && sudo systemctl disable vsftpd",
            "# Switch to SFTP (uses SSH):",
            "sudo apt install openssh-server  # or: sudo pacman -S openssh",
            "# Configure /etc/ssh/sshd_config:",
            "# Subsystem sftp /usr/lib/openssh/sftp-server"
        ]
    },
    "telnet": {
        "service": "Telnet",
        "risk_summary": "Telnet is completely unencrypted. All data including passwords is visible on the wire.",
        "steps": [
            "Disable Telnet immediately",
            "Replace with SSH for remote access"
        ],
        "commands": [
            "sudo systemctl stop telnet.socket && sudo systemctl disable telnet.socket",
            "sudo systemctl stop inetd && sudo systemctl disable inetd",
            "# Use SSH instead:",
            "sudo apt install openssh-server && sudo systemctl enable sshd"
        ]
    },
    "ssh": {
        "service": "SSH",
        "risk_summary": "SSH is generally secure but outdated versions have known exploits.",
        "steps": [
            "Update OpenSSH to the latest version",
            "Disable root login and password authentication",
            "Use key-based authentication only",
            "Change default port if desired"
        ],
        "commands": [
            "sudo apt update && sudo apt upgrade openssh-server",
            "# Edit /etc/ssh/sshd_config:",
            "# PermitRootLogin no",
            "# PasswordAuthentication no",
            "# PubkeyAuthentication yes",
            "sudo systemctl restart sshd"
        ]
    },
    "http": {
        "service": "HTTP",
        "risk_summary": "HTTP serves traffic without encryption. Vulnerable to MITM attacks.",
        "steps": [
            "Enable HTTPS with a valid TLS certificate",
            "Redirect all HTTP traffic to HTTPS",
            "Update the web server to the latest version",
            "Enable security headers (HSTS, CSP, X-Frame-Options)"
        ],
        "commands": [
            "# Install certbot for free TLS certs:",
            "sudo apt install certbot python3-certbot-apache",
            "sudo certbot --apache -d yourdomain.com",
            "# Or for nginx:",
            "sudo certbot --nginx -d yourdomain.com",
            "# Force HTTPS redirect in Apache:",
            "# RewriteEngine On",
            "# RewriteCond %{HTTPS} off",
            "# RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"
        ]
    },
    "smb": {
        "service": "SMB",
        "risk_summary": "SMB (port 445) is a frequent target for ransomware and lateral movement (e.g., EternalBlue).",
        "steps": [
            "Block SMB from the internet (firewall port 445)",
            "Disable SMBv1 completely",
            "Keep systems patched against known SMB exploits"
        ],
        "commands": [
            "# Block SMB at firewall:",
            "sudo ufw deny 445/tcp",
            "# Disable SMBv1 on Linux:",
            "echo 'min protocol = SMB2' | sudo tee -a /etc/samba/smb.conf",
            "sudo systemctl restart smbd"
        ]
    },
    "rdp": {
        "service": "RDP",
        "risk_summary": "RDP exposed to the internet is a top target for brute-force and ransomware attacks.",
        "steps": [
            "Never expose RDP directly to the internet",
            "Use a VPN or SSH tunnel for remote access",
            "Enable Network Level Authentication (NLA)",
            "Enforce strong passwords and account lockout"
        ],
        "commands": [
            "# Block RDP at firewall:",
            "sudo ufw deny 3389/tcp",
            "# Use SSH tunnel instead:",
            "ssh -L 3389:localhost:3389 user@remote-server",
            "# Then connect RDP to localhost:3389"
        ]
    },
    "mysql": {
        "service": "MySQL",
        "risk_summary": "MySQL exposed externally can lead to data exfiltration and unauthorized access.",
        "steps": [
            "Bind MySQL to localhost only",
            "Require SSL for remote connections",
            "Remove default/anonymous accounts",
            "Use strong passwords"
        ],
        "commands": [
            "# Edit /etc/mysql/mysql.conf.d/mysqld.cnf:",
            "# bind-address = 127.0.0.1",
            "sudo systemctl restart mysql",
            "# Remove anonymous users:",
            "sudo mysql_secure_installation",
            "# Block external access:",
            "sudo ufw deny 3306/tcp"
        ]
    },
    "mongodb": {
        "service": "MongoDB",
        "risk_summary": "MongoDB without authentication is trivially exploitable. Data can be stolen or ransomed.",
        "steps": [
            "Enable authentication",
            "Bind to localhost only",
            "Use TLS for connections",
            "Keep MongoDB updated"
        ],
        "commands": [
            "# Edit /etc/mongod.conf:",
            "# net:",
            "#   bindIp: 127.0.0.1",
            "# security:",
            "#   authorization: enabled",
            "sudo systemctl restart mongod",
            "sudo ufw deny 27017/tcp"
        ]
    },
    "redis": {
        "service": "Redis",
        "risk_summary": "Redis without authentication allows arbitrary command execution and data theft.",
        "steps": [
            "Set a strong password (requirepass)",
            "Bind to localhost only",
            "Disable dangerous commands (FLUSHALL, CONFIG, DEBUG)",
            "Enable TLS if available"
        ],
        "commands": [
            "# Edit /etc/redis/redis.conf:",
            "# bind 127.0.0.1",
            "# requirepass YourStrongPasswordHere",
            "# rename-command FLUSHALL \"\"",
            "# rename-command CONFIG \"\"",
            "sudo systemctl restart redis",
            "sudo ufw deny 6379/tcp"
        ]
    },
    "snmp": {
        "service": "SNMP",
        "risk_summary": "SNMP v1/v2c uses community strings (essentially plaintext passwords). Can leak full system info.",
        "steps": [
            "Upgrade to SNMPv3 with authentication and encryption",
            "Change default community strings (public/private)",
            "Restrict SNMP access to management network only"
        ],
        "commands": [
            "# Block SNMP from external access:",
            "sudo ufw deny 161/udp",
            "# Edit /etc/snmp/snmpd.conf to use SNMPv3:",
            "# rouser myuser authpriv",
            "sudo systemctl restart snmpd"
        ]
    }
}

# Map ports to remediation keys
PORT_TO_REMEDIATION = {
    21: "ftp",
    23: "telnet",
    22: "ssh",
    80: "http",
    8080: "http",
    443: "http",
    8443: "http",
    445: "smb",
    139: "smb",
    3389: "rdp",
    5900: "rdp",
    3306: "mysql",
    27017: "mongodb",
    6379: "redis",
    161: "snmp",
}


def compute_risk_score(port, cvss_scores, is_internet_facing=True):
    """
    Compute a composite risk score for a single port.
    Formula: max_cvss × port_exposure × internet_factor
    Capped at 10.0.
    """
    # Base CVSS — use the highest one, or a default if no CVEs found
    if cvss_scores:
        numeric_scores = [s for s in cvss_scores if isinstance(s, (int, float))]
        max_cvss = max(numeric_scores) if numeric_scores else 3.0
    else:
        max_cvss = 2.0  # Low baseline if no CVEs

    # Port exposure multiplier
    exposure = PORT_EXPOSURE.get(port, 1.0)

    # Internet-facing factor
    inet_factor = 1.2 if is_internet_facing else 0.8

    score = max_cvss * exposure * inet_factor
    # Normalize to 0-10 scale
    score = min(score / 2.5, 10.0)
    score = round(score, 1)
    return score


def get_severity(score):
    """Map a 0-10 score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 1.0:
        return "LOW"
    else:
        return "INFO"


def get_remediation(port, service_name=None):
    """Look up remediation advice for a given port or service name."""
    key = PORT_TO_REMEDIATION.get(port)
    if not key and service_name:
        key = service_name.lower()
    if key and key in REMEDIATION_DB:
        return REMEDIATION_DB[key]
    return None


def assess_risk(scan_results):
    """
    Takes a scan_results dict (from run_scan) and enriches it with
    risk scores and remediation for each port.
    Returns a risk summary dict.
    """
    port_risks = {}
    all_scores = []

    open_ports = scan_results.get("open_ports", {})
    
    for port_str, data in open_ports.items():
        port = int(port_str)
        
        # Extract CVSS scores from vulnerabilities
        cvss_scores = []
        for vuln in data.get("vulnerabilities", []):
            score = vuln.get("score")
            if isinstance(score, (int, float)):
                cvss_scores.append(score)
        
        # Compute risk
        risk_score = compute_risk_score(port, cvss_scores)
        severity = get_severity(risk_score)
        remediation = get_remediation(port, data.get("mapped_service"))
        
        port_risks[port_str] = {
            "risk_score": risk_score,
            "severity": severity,
            "cvss_scores": cvss_scores,
            "remediation": remediation
        }
        all_scores.append(risk_score)

    # Overall target risk: weighted average biased toward highest
    if all_scores:
        overall = round(
            (max(all_scores) * 0.6) + (sum(all_scores) / len(all_scores) * 0.4),
            1
        )
        overall = min(overall, 10.0)
    else:
        overall = 0.0

    return {
        "overall_score": overall,
        "overall_severity": get_severity(overall),
        "port_risks": port_risks,
        "total_ports_scanned": len(open_ports)
    }
