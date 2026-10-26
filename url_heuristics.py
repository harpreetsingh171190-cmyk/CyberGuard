"""Explainable, offline URL indicators. Heuristics are triage signals, not a classifier."""
import ipaddress
import re
from urllib.parse import urlsplit, unquote

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy"}
SUSPICIOUS_WORDS = {"login", "verify", "secure", "account", "update", "wallet", "password", "billing", "invoice", "gift", "prize", "urgent", "recover"}


def analyze_url(url):
    p = urlsplit(url.strip())
    host = (p.hostname or "").lower().rstrip(".")
    decoded = unquote(url)
    score, findings = 0, []
    def add(points, message):
        nonlocal score
        score += points
        findings.append({"points": points, "indicator": message})
    if p.scheme.lower() != "https": add(10, "Uses HTTP rather than HTTPS")
    try:
        ipaddress.ip_address(host)
        add(20, "Host is an IP address instead of a domain name")
    except ValueError:
        pass
    if "xn--" in host: add(15, "Internationalized/punycode hostname; inspect for lookalikes")
    if host in SHORTENERS: add(15, "URL uses a known link-shortening domain")
    labels = host.split(".") if host else []
    if len(labels) >= 5: add(10, "Hostname has many subdomain levels")
    if len(host) >= 45: add(10, "Unusually long hostname")
    if p.username is not None or "@" in p.netloc: add(20, "Contains user-info or @ syntax that can disguise the destination")
    try:
        if p.port and p.port not in (80, 443): add(10, "Uses a non-standard web port")
    except ValueError:
        add(10, "Contains an invalid port")
    if len(url) > 180: add(10, "Unusually long URL")
    if url.count("%") >= 4 or re.search(r"%[0-9a-fA-F]{2}", decoded) and decoded != url:
        add(5, "Contains extensive or nested URL encoding")
    if sum(ch.isdigit() for ch in host) >= 7: add(5, "Hostname contains many digits")
    words = sorted(w for w in SUSPICIOUS_WORDS if w in (host + " " + p.path + " " + p.query).lower())
    if words: add(min(15, 5 + 2 * (len(words)-1)), "Contains sensitive-action terms: " + ", ".join(words))
    score = min(100, score)
    level = "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    return {"score": score, "level": level, "findings": findings,
            "components": {"scheme": p.scheme, "hostname": host, "port": p.port, "path": p.path, "query_present": bool(p.query), "fragment_present": bool(p.fragment)},
            "note": "Offline heuristic only; it can produce false positives/negatives and does not replace reputation checks."}
