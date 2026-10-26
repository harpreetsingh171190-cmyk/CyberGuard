"""Simple local domain allow/block lists; exact host and subdomains match."""
import json, os
from urllib.parse import urlsplit
PATH = os.getenv("CYBERGUARD_LISTS_PATH", "domain_lists.json")
DEFAULT = {"allow": [], "block": []}

def load_lists():
    try:
        with open(PATH, encoding="utf-8") as f: data=json.load(f)
        if not isinstance(data, dict): raise ValueError
        return {k: sorted(set(str(x).strip().lower().rstrip(".") for x in data.get(k, []) if str(x).strip())) for k in ("allow","block")}
    except FileNotFoundError: return {k:list(v) for k,v in DEFAULT.items()}

def save_lists(data):
    clean={k: sorted(set(str(x).strip().lower().rstrip(".") for x in data.get(k,[]) if str(x).strip())) for k in ("allow","block")}
    for values in clean.values():
        for host in values:
            if ":" in host or "/" in host or " " in host or not host: raise ValueError("Enter hostnames only, such as example.com")
    with open(PATH,"w",encoding="utf-8") as f: json.dump(clean,f,indent=2)
    return clean

def match_domain(url, lists=None):
    lists=lists or load_lists()
    host=(urlsplit(url).hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    for kind in ("block","allow"):
        for domain in lists.get(kind,[]):
            try: normalized=domain.encode("idna").decode("ascii").lower().rstrip(".")
            except UnicodeError: continue
            if host == normalized or host.endswith("."+normalized): return kind, normalized
    return "", ""
