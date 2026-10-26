"""Offline clustering of URL indicators into possible phishing/campaign groups."""
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from urllib.parse import urlsplit
import ipaddress


def _host_path(url):
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    labels = host.split(".") if host else []
    registrable_hint = ".".join(labels[-2:]) if len(labels) >= 2 and not is_ip else host
    path_parts = [p.lower() for p in parsed.path.split("/") if p]
    query_keys = sorted({x.split("=", 1)[0].lower() for x in parsed.query.split("&") if x})
    return host, registrable_hint, path_parts, query_keys, is_ip


def cluster_indicators(urls, similarity_threshold=0.78, max_pairs=5000):
    """Summarize repeated hosts and likely related URL indicators without network access."""
    if not 0.5 <= float(similarity_threshold) <= 1.0:
        raise ValueError("similarity_threshold must be between 0.5 and 1.0")
    clean = list(dict.fromkeys(str(u).strip() for u in urls if str(u).strip()))
    parsed = [(u, *_host_path(u)) for u in clean]
    counts = Counter(item[1] for item in parsed)
    host_rows = []
    host_seen = set()
    for url, host, registrable, parts, keys, is_ip in parsed:
        if host in host_seen:
            continue
        host_seen.add(host)
        host_rows.append({"host": host, "url_count": counts[host], "registrable_hint": registrable,
                          "ip_literal": is_ip, "sample_url": next(x[0] for x in parsed if x[1] == host)})

    pairs = []
    examined = 0
    for i in range(len(host_rows)):
        for j in range(i + 1, len(host_rows)):
            if examined >= max_pairs:
                break
            examined += 1
            a, b = host_rows[i], host_rows[j]
            ha, hb = a["host"], b["host"]
            ratio = SequenceMatcher(None, ha, hb).ratio()
            # Avoid reporting trivial same-suffix matches as likely typosquats.
            same_suffix = ha.split(".")[-1:] == hb.split(".")[-1:]
            if ratio >= similarity_threshold and same_suffix:
                pairs.append({"host_a": ha, "host_b": hb, "similarity": round(ratio, 3),
                              "reason": "similar hostname spelling; manually verify"})
    shared_path = defaultdict(list)
    for url, host, registrable, parts, keys, is_ip in parsed:
        if parts:
            shared_path[parts[0]].append({"url": url, "host": host})
    path_groups = [{"path_prefix": prefix, "count": len(items), "hosts": sorted({x["host"] for x in items}),
                    "urls": [x["url"] for x in items[:20]]}
                   for prefix, items in shared_path.items() if len(items) >= 2]
    path_groups.sort(key=lambda x: (-x["count"], x["path_prefix"]))
    return {"schema": "cyberguard-campaign-clusters-v1", "indicator_count": len(clean),
            "unique_host_count": len(host_rows), "hosts": host_rows,
            "similar_hostname_pairs": pairs, "shared_path_prefix_groups": path_groups,
            "pairs_examined": examined, "pair_limit": max_pairs,
            "note": "Offline similarity hints only. Public-suffix handling is approximate; similarity and shared paths do not prove common ownership or maliciousness."}
