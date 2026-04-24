import requests
import subprocess
import re
import platform

GEO_PROVIDERS = [
    {
        "name": "ipapi.co",
        "url": "https://ipapi.co/{ip}/json/",
        "map": {
            "ip": "ip",
            "country": "country_name",
            "country_code": "country_code",
            "city": "city",
            "region": "region",
            "latitude": "latitude",
            "longitude": "longitude",
            "isp": "org",
            "asn": "asn",
        }
    },
    {
        "name": "ip-api.com",
        "url": "http://ip-api.com/json/{ip}",
        "map": {
            "ip": "query",
            "country": "country",
            "country_code": "countryCode",
            "city": "city",
            "region": "regionName",
            "latitude": "lat",
            "longitude": "lon",
            "isp": "isp",
            "asn": "as",
        }
    },
    {
        "name": "ipwho.is",
        "url": "https://ipwho.is/{ip}",
        "map": {
            "ip": "ip",
            "country": "country",
            "country_code": "country_code",
            "city": "city",
            "region": "region",
            "latitude": "latitude",
            "longitude": "longitude",
            "isp": "connection.isp",
            "asn": "connection.asn",
        }
    }
]


def _get_nested(data, key):
    """Get a nested key like 'connection.isp' from a dict."""
    keys = key.split(".")
    val = data
    for k in keys:
        if isinstance(val, dict):
            val = val.get(k)
        else:
            return None
    return val


def lookup_geo(ip):
    """
    Try multiple free geo-IP providers with automatic failover.
    Returns a normalized dict with geo information or an error.
    """
    for provider in GEO_PROVIDERS:
        try:
            url = provider["url"].format(ip=ip)
            resp = requests.get(url, timeout=5, headers={"User-Agent": "VulScan/2.0"})
            if resp.status_code == 200:
                raw = resp.json()
                # Some providers return error flags
                if raw.get("error") or raw.get("status") == "fail":
                    continue
                
                geo = {"provider": provider["name"]}
                for our_key, their_key in provider["map"].items():
                    geo[our_key] = _get_nested(raw, their_key)
                return geo
        except Exception:
            continue
    
    return {"error": "All geo-IP providers failed", "ip": ip}


def run_traceroute(target, max_hops=20):
    """
    Run a system traceroute and parse the output.
    Returns a list of hops with IP addresses and RTT.
    """
    hops = []
    system = platform.system().lower()

    try:
        if system == "windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), target]
        else:
            # Try traceroute first, fall back to tracepath
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", target]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout

        # Parse each line for hop data
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Match lines like: " 1  192.168.1.1  1.234 ms  ..."
            hop_match = re.match(r'^\s*(\d+)\s+(.+)', line)
            if not hop_match:
                continue

            hop_num = int(hop_match.group(1))
            rest = hop_match.group(2)

            # Extract IP addresses from the line
            ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rest)
            
            # Extract RTT values
            rtt_matches = re.findall(r'([\d.]+)\s*ms', rest)

            if ip_matches:
                hop_ip = ip_matches[0]
                avg_rtt = None
                if rtt_matches:
                    rtts = [float(r) for r in rtt_matches]
                    avg_rtt = round(sum(rtts) / len(rtts), 2)
                
                hops.append({
                    "hop": hop_num,
                    "ip": hop_ip,
                    "rtt_ms": avg_rtt
                })
            else:
                # Timeout hop (usually shows * * *)
                hops.append({
                    "hop": hop_num,
                    "ip": "*",
                    "rtt_ms": None
                })
    except FileNotFoundError:
        # traceroute not installed, try tracepath
        try:
            result = subprocess.run(
                ["tracepath", "-n", target],
                capture_output=True,
                text=True,
                timeout=60
            )
            for line in result.stdout.strip().split("\n"):
                hop_match = re.match(r'^\s*(\d+):\s+(\S+)', line)
                if hop_match:
                    hop_num = int(hop_match.group(1))
                    hop_ip = hop_match.group(2)
                    rtt_match = re.search(r'([\d.]+)\s*ms', line)
                    rtt = float(rtt_match.group(1)) if rtt_match else None
                    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hop_ip):
                        hops.append({"hop": hop_num, "ip": hop_ip, "rtt_ms": rtt})
        except Exception:
            pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return hops


def get_topology(target_ip, max_hops=20):
    """
    Full geo-enriched topology: target geo + traceroute with per-hop geo.
    Returns a dict with target_geo and topology list.
    """
    target_geo = lookup_geo(target_ip)
    hops = run_traceroute(target_ip, max_hops)
    
    # Enrich each hop with geo data (skip private/timeout IPs)
    enriched_hops = []
    for hop in hops:
        hop_data = dict(hop)
        ip = hop["ip"]
        if ip != "*" and not _is_private(ip):
            hop_data["geo"] = lookup_geo(ip)
        else:
            hop_data["geo"] = None
        enriched_hops.append(hop_data)

    return {
        "target_ip": target_ip,
        "target_geo": target_geo,
        "hops": enriched_hops,
        "total_hops": len(enriched_hops)
    }


def _is_private(ip):
    """Check if an IP is in a private range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    return False
