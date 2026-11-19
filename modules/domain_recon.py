import socket
import time
from urllib.parse import urlparse
import dns.resolver
import requests
import whois


def normalize_domain(raw_input):
    """Cleans URLs or email addresses into a bare domain name."""
    raw_input = raw_input.strip().lower()
    if "@" in raw_input and "://" not in raw_input:
        return raw_input.split("@")[-1]
    if "://" in raw_input:
        parsed = urlparse(raw_input)
        host = parsed.netloc
    else:
        host = raw_input.split("/")[0]
    return host.lstrip("www.").split(":")[0]


def _get_dns_resolver():
    """Creates a cross-platform DNS resolver (handles Android/Termux cleanly)."""
    try:
        resolver = dns.resolver.Resolver()
        if not resolver.nameservers:
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    except Exception:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 5
    resolver.lifetime = 6
    return resolver


def _format_whois_value(val):
    if isinstance(val, list):
        cleaned = [str(v) for v in val if v]
        return cleaned[0] if len(cleaned) == 1 else cleaned[:4]
    return str(val) if val else None


def run_domain_recon(target):
    """Performs passive DNS, WHOIS, IP, and HTTP header reconnaissance on a domain."""
    domain = normalize_domain(target)
    start = time.perf_counter()

    report = {
        "target_domain": domain,
        "ip_address": None,
        "dns_records": {},
        "email_security": {
            "has_mx": False,
            "has_spf": False,
            "has_dmarc": False,
        },
        "whois": {},
        "http_headers": {},
        "execution_time_sec": 0,
    }

    # 1. IP Resolution
    try:
        report["ip_address"] = socket.gethostbyname(domain)
    except socket.gaierror:
        report["ip_address"] = "Unresolved"

    # 2. DNS Enumeration
    resolver = _get_dns_resolver()
    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records = [str(rdata).strip() for rdata in answers]
            report["dns_records"][rtype] = records
        except Exception:
            report["dns_records"][rtype] = []

    if report["dns_records"].get("MX"):
        report["email_security"]["has_mx"] = True
    for txt in report["dns_records"].get("TXT", []):
        if "v=spf1" in txt.lower():
            report["email_security"]["has_spf"] = True

    # Check DMARC TXT record
    try:
        dmarc_ans = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(r).strip() for r in dmarc_ans]
        if any("v=dmarc1" in r.lower() for r in dmarc_records):
            report["email_security"]["has_dmarc"] = True
            report["dns_records"]["DMARC"] = dmarc_records
    except Exception:
        report["dns_records"]["DMARC"] = []

    # 3. Public WHOIS Registration Lookup
    try:
        w = whois.whois(domain)
        whois_fields = {
            "registrar": _format_whois_value(w.registrar),
            "creation_date": _format_whois_value(w.creation_date),
            "expiration_date": _format_whois_value(w.expiration_date),
            "org": _format_whois_value(getattr(w, "org", None)),
            "country": _format_whois_value(getattr(w, "country", None)),
            "name_servers": _format_whois_value(w.name_servers),
        }
        report["whois"] = {k: v for k, v in whois_fields.items() if v}
    except Exception as exc:
        report["whois"] = {"error": f"WHOIS unavailable: {str(exc)[:100]}"}

    # 4. Passive HTTP Security Headers Inspection
    try:
        resp = requests.head(
            f"https://{domain}",
            timeout=6,
            allow_redirects=True,
            headers={"User-Agent": "OSINT-Academic-Recon-Tool/1.0"},
        )
        interesting = [
            "Server",
            "X-Powered-By",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]
        report["http_headers"] = {
            h: resp.headers.get(h, "Missing") for h in interesting
        }
        report["http_headers"]["Final-URL"] = resp.url
        report["http_headers"]["Status-Code"] = resp.status_code
    except Exception as exc:
        report["http_headers"] = {"error": f"HTTPS unreachable: {str(exc)[:80]}"}

    report["execution_time_sec"] = round(time.perf_counter() - start, 2)
    return report
