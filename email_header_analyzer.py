"""Offline, conservative analysis of pasted email headers; no message is sent or fetched."""
from __future__ import annotations
from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re

AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I)


def _domain(address: str) -> str:
    address = parseaddr(address or "")[1].strip().lower()
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].rstrip(".")


def analyze_email_headers(raw_headers: str) -> dict:
    """Return explainable indicators from raw headers, without claiming proof of spoofing."""
    raw = str(raw_headers or "")[:200_000]
    msg = Parser(policy=policy.default).parsestr(raw, headersonly=True)
    from_value = str(msg.get("From", ""))
    reply_value = str(msg.get("Reply-To", ""))
    return_value = str(msg.get("Return-Path", ""))
    from_domain = _domain(from_value)
    reply_domain = _domain(reply_value)
    return_domain = _domain(return_value)
    auth_text = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    auth = {}
    for method, result in AUTH_RE.findall(auth_text):
        auth[method.lower()] = result.lower()
    findings = []
    def add(severity, code, detail):
        findings.append({"severity": severity, "code": code, "detail": detail})
    if not from_value:
        add("medium", "MISSING_FROM", "No From header was found in the supplied text.")
    if reply_domain and from_domain and reply_domain != from_domain:
        add("medium", "REPLY_TO_DOMAIN_MISMATCH", "Reply-To domain differs from From domain; this can be legitimate but merits review.")
    if return_domain and from_domain and return_domain != from_domain:
        add("low", "RETURN_PATH_DOMAIN_MISMATCH", "Return-Path domain differs from From domain; mailing services can cause this legitimately.")
    for method, result in auth.items():
        if result in {"fail", "softfail", "permerror"}:
            add("high" if result == "fail" else "medium", f"{method.upper()}_{result.upper()}", f"Authentication-Results reports {method}={result}.")
        elif result in {"none", "neutral", "temperror"}:
            add("low", f"{method.upper()}_{result.upper()}", f"Authentication-Results reports {method}={result}; interpret in context.")
    if not auth:
        add("low", "NO_AUTH_RESULTS", "No recognizable SPF/DKIM/DMARC result was found in Authentication-Results.")
    received_count = len(msg.get_all("Received", []))
    if received_count == 0:
        add("low", "NO_RECEIVED_HEADERS", "No Received headers found; the pasted data may be incomplete.")
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = max((x["severity"] for x in findings), key=lambda s: rank[s], default="none")
    return {"from": from_value, "from_domain": from_domain, "reply_to": reply_value,
            "reply_to_domain": reply_domain, "return_path_domain": return_domain,
            "authentication_results": auth, "received_hops": received_count,
            "findings": findings, "finding_count": len(findings), "highest_severity": highest,
            "note": "Offline header triage only. Headers can be incomplete or forged; verify using trusted mail infrastructure and message context."}
