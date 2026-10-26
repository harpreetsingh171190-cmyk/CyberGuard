"""Simple, local-first threat-hunting rules. Uses literal matching, never executes rules."""
from __future__ import annotations

DEFAULT_RULES = [
    {"id": "URL-001", "name": "Defanged URL indicator", "pattern": "hxxp", "severity": "medium", "category": "url_obfuscation", "description": "Text contains a commonly defanged URL scheme."},
    {"id": "AUTH-001", "name": "Credential theft wording", "pattern": "verify your password", "severity": "high", "category": "credential_phishing", "description": "Text contains credential-verification wording."},
    {"id": "AUTH-002", "name": "Urgent account warning", "pattern": "account will be suspended", "severity": "medium", "category": "social_engineering", "description": "Text contains an account-pressure phrase."},
    {"id": "PAY-001", "name": "Payment redirection wording", "pattern": "update your payment", "severity": "medium", "category": "payment_phishing", "description": "Text contains a payment-update phrase."},
    {"id": "IOC-001", "name": "IP address indicator", "pattern": "http://", "severity": "low", "category": "network_indicator", "description": "Text contains a plain HTTP scheme; review context."},
]


def validate_rules(rules):
    if not isinstance(rules, list):
        raise ValueError("Rules must be a list")
    cleaned, seen = [], set()
    for idx, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule {idx} must be an object")
        rid = str(rule.get("id", f"CUSTOM-{idx}")).strip()[:64]
        name = str(rule.get("name", rid)).strip()[:120]
        pattern = str(rule.get("pattern", "")).strip()[:300]
        severity = str(rule.get("severity", "medium")).lower()
        if not rid or rid in seen:
            raise ValueError(f"Missing or duplicate rule id: {rid}")
        if not pattern:
            raise ValueError(f"Rule {rid} needs a literal pattern")
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"Rule {rid} has invalid severity")
        seen.add(rid)
        cleaned.append({"id": rid, "name": name or rid, "pattern": pattern,
                        "severity": severity, "category": str(rule.get("category", "custom"))[:80],
                        "description": str(rule.get("description", ""))[:500]})
    return cleaned


def scan_text(text, rules=None):
    """Match literal patterns against bounded text; return findings and summary."""
    content = str(text or "")[:1_000_000]
    rules = validate_rules(DEFAULT_RULES if rules is None else rules)
    findings = []
    folded = content.casefold()
    for rule in rules:
        pattern = rule["pattern"].casefold()
        count = folded.count(pattern)
        if count:
            findings.append({"rule_id": rule["id"], "name": rule["name"],
                             "severity": rule["severity"], "category": rule["category"],
                             "match_count": count, "description": rule["description"],
                             "pattern": rule["pattern"]})
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    max_severity = max((f["severity"] for f in findings), key=lambda x: rank[x], default="none")
    return {"findings": findings, "matched_rules": len(findings), "max_severity": max_severity,
            "text_characters_scanned": len(content), "note": "Literal-match triage only; a match is not proof of malicious activity."}
