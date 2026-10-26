"""Safe URL utilities; never resolves DNS or visits submitted sites."""
from urllib.parse import urlsplit, urlunsplit
import ipaddress
import hashlib
import re


def defang_url(url: str) -> str:
    """Make a URL less clickable for incident reports."""
    value = (url or "").strip()
    value = value.replace("https://", "hxxps://", 1).replace("http://", "hxxp://", 1)
    value = value.replace(".", "[.]")
    value = value.replace("@", "[@]")
    return value


def normalize_url(url: str) -> str:
    """Conservative normalization for comparison; preserves path/query semantics."""
    p = urlsplit((url or "").strip())
    scheme = p.scheme.lower()
    host = (p.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    if not host:
        raise ValueError("URL must contain a hostname")
    try:
        port = p.port
    except ValueError as exc:
        raise ValueError("Invalid port") from exc
    if (scheme, port) in (("http", 80), ("https", 443)):
        port = None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = p.path or "/"
    return urlunsplit((scheme, netloc, path, p.query, ""))


def url_facts(url: str) -> dict:
    p = urlsplit((url or "").strip())
    host = (p.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    return {
        "scheme": p.scheme.lower(), "hostname": host, "is_ip_address": is_ip,
        "subdomain_count": max(0, len(host.split(".")) - 2) if not is_ip else 0,
        "path_depth": len([part for part in p.path.split("/") if part]),
        "query_parameter_count": len([x for x in p.query.split("&") if x]) if p.query else 0,
        "has_fragment": bool(p.fragment), "url_length": len(url or "")
    }


def url_fingerprint(url: str) -> str:
    """Stable SHA-256 fingerprint of the exact UTF-8 URL string."""
    return hashlib.sha256((url or "").encode("utf-8")).hexdigest()


def extract_urls(text: str) -> list[str]:
    """Extract URL-like indicators from text without opening or resolving them."""
    pattern = re.compile(r"(?i)\b(?:https?://|hxxps?://)[^\s<>\"']+")
    found = []
    seen = set()
    for match in pattern.findall(text or ""):
        value = match.rstrip(".,;:!?)\\]}")
        value = value.replace("hxxps://", "https://").replace("hxxp://", "http://")
        if value and value not in seen:
            seen.add(value)
            found.append(value)
    return found
