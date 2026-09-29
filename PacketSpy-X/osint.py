import socket
import whois
import requests

geo_cache = {}

def ip_osint(target):
    result = {
        "target": target,
        "resolved_ip": None,
        "whois": {},
        "geo": {}
    }

    # DNS Resolution
    try:
        ip = socket.gethostbyname(target)
        result["resolved_ip"] = ip
    except:
        ip = target
        result["resolved_ip"] = ip

    # WHOIS
    try:
        w = whois.whois(target)
        result["whois"] = {
            "domain_name": str(w.domain_name),
            "registrar": str(w.registrar),
            "country": str(w.country),
            "org": str(w.org)
        }
    except:
        result["whois"] = {"error": "WHOIS lookup failed"}

    # GeoIP Lookup (Cached)
    if ip not in geo_cache:
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()

            geo_cache[ip] = {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as")
            }
        except:
            geo_cache[ip] = {"error": "Geo lookup failed"}

    result["geo"] = geo_cache[ip]

    return result