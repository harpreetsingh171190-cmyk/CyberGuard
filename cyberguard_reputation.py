"""Privacy-conscious, read-only URL reputation checks for CyberGuard."""
import os, base64
from urllib.parse import urlsplit
import requests

TIMEOUT_SECONDS = 12

def _validate_url(url):
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise ValueError("URL must be a non-empty string of at most 2048 characters.")
    value = url.strip()
    p = urlsplit(value)
    if p.scheme.lower() not in {"http", "https"} or not p.hostname:
        raise ValueError("Only absolute http(s) URLs are accepted.")
    if p.username or p.password:
        raise ValueError("URLs with embedded credentials are not accepted.")
    try: p.port
    except ValueError as exc: raise ValueError("Invalid URL port.") from exc
    return value

def check_google_safe_browsing(url, api_key=None):
    key = api_key or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key: return {"provider":"Google Safe Browsing", "status":"not_configured"}
    url = _validate_url(url)
    payload = {"client":{"clientId":"cyberguard-url-scanner","clientVersion":"1.0"},
      "threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
      "platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}}
    try:
        r=requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key":key}, json=payload, timeout=TIMEOUT_SECONDS)
        if r.status_code == 429: return {"provider":"Google Safe Browsing", "status":"rate_limited"}
        r.raise_for_status(); matches=r.json().get("matches", [])
        return {"provider":"Google Safe Browsing", "status":"malicious" if matches else "no_match",
                "matches":[{"threatType":m.get("threatType"),"platformType":m.get("platformType")} for m in matches]}
    except requests.Timeout: return {"provider":"Google Safe Browsing", "status":"error", "message":"timeout"}
    except (requests.RequestException, ValueError): return {"provider":"Google Safe Browsing", "status":"error", "message":"request/response error"}

def check_virustotal_report(url, api_key=None):
    """Retrieve existing report only; never submits a new scan."""
    key=api_key or os.getenv("VIRUSTOTAL_API_KEY")
    if not key: return {"provider":"VirusTotal", "status":"not_configured"}
    url=_validate_url(url); uid=base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        r=requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey":key,"accept":"application/json"}, timeout=TIMEOUT_SECONDS)
        if r.status_code == 404: return {"provider":"VirusTotal", "status":"not_found"}
        if r.status_code == 429: return {"provider":"VirusTotal", "status":"rate_limited"}
        r.raise_for_status(); a=r.json().get("data",{}).get("attributes",{}); s=a.get("last_analysis_stats",{})
        return {"provider":"VirusTotal", "status":"malicious" if s.get("malicious",0) else ("suspicious" if s.get("suspicious",0) else "no_detection"),
                "last_analysis_stats":s,"reputation":a.get("reputation"),"last_analysis_date":a.get("last_analysis_date")}
    except requests.Timeout: return {"provider":"VirusTotal", "status":"error", "message":"timeout"}
    except (requests.RequestException, ValueError, TypeError): return {"provider":"VirusTotal", "status":"error", "message":"request/response error"}

def check_live_reputation(url, providers=("google","virustotal")):
    url=_validate_url(url); results=[]
    if "google" in providers: results.append(check_google_safe_browsing(url))
    if "virustotal" in providers: results.append(check_virustotal_report(url))
    if any(x.get("status") in {"malicious","suspicious"} for x in results): verdict="THREAT INDICATED"
    elif results and all(x.get("status") in {"no_match","no_detection","not_found"} for x in results): verdict="NO KNOWN THREAT FOUND — NOT A SAFETY GUARANTEE"
    else: verdict="INCONCLUSIVE — CHECK CONFIGURATION/STATUS"
    return {"url":url,"verdict":verdict,"provider_results":results,
            "note":"Providers receive the queried URL. Do not query confidential URLs. No match does not prove safety."}
