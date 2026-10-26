"""Bounded static content-signature scanner. Never executes or extracts file content."""
from __future__ import annotations
import hashlib
import re
from pathlib import Path

DEFAULT_SIGNATURES = [
    {"id":"PS_ENCODED_COMMAND","severity":"high","category":"script","pattern":r"(?i)\bpowershell(?:\.exe)?\b.{0,80}(?:-enc(?:odedcommand)?|-e\s+[A-Za-z0-9+/]{12,})","description":"PowerShell command with an encoded-command option."},
    {"id":"SCRIPT_DOWNLOAD_EXEC","severity":"high","category":"script","pattern":r"(?i)(?:Invoke-WebRequest|iwr|curl|wget).{0,120}(?:\||;|&&).{0,80}(?:Invoke-Expression|\biex\b|powershell)","description":"Possible script download followed by execution pattern."},
    {"id":"AUTOEXEC_MACRO","severity":"medium","category":"document","pattern":r"(?i)\b(?:AutoOpen|Document_Open|Workbook_Open|AutoExec)\b","description":"Office/VBA-style auto-execution macro name."},
    {"id":"EVAL_EXEC","severity":"medium","category":"script","pattern":r"(?i)\b(?:eval|exec)\s*\(","description":"Dynamic evaluation/execution call; context determines risk."},
    {"id":"OBFUSCATED_JS","severity":"medium","category":"script","pattern":r"(?i)\batob\s*\(|String\.fromCharCode\s*\(","description":"JavaScript decoding/obfuscation primitive."},
    {"id":"SUSPICIOUS_PERSISTENCE","severity":"high","category":"system","pattern":r"(?i)(?:CurrentVersion\\Run|schtasks\s+/create|LaunchAgents|systemctl\s+enable)","description":"Potential persistence-related command or path."},
]
MAX_SCAN_BYTES = 2 * 1024 * 1024

def scan_content(filename: str, data: bytes, signatures=None) -> dict:
    raw = bytes(data[:MAX_SCAN_BYTES])
    text = raw.decode("utf-8", errors="replace")
    sigs = DEFAULT_SIGNATURES if signatures is None else signatures
    findings=[]
    for sig in sigs:
        try:
            match = re.search(sig["pattern"], text)
        except (re.error, KeyError, TypeError):
            continue
        if match:
            start=max(0, match.start()-45); end=min(len(text), match.end()+45)
            snippet=re.sub(r"\s+", " ", text[start:end])[:180]
            findings.append({"id":str(sig.get("id","CUSTOM")),"severity":str(sig.get("severity","medium")).lower(),"category":str(sig.get("category","custom")),"description":str(sig.get("description","Matched custom signature")),"offset":match.start(),"evidence_snippet":snippet})
    order={"critical":4,"high":3,"medium":2,"low":1,"info":0}
    highest=max((f["severity"] for f in findings), key=lambda x:order.get(x,0), default="info")
    name=Path(str(filename).replace('\\','/')).name[:255] or "unnamed"
    return {"filename":name,"bytes_scanned":len(raw),"truncated":len(data)>MAX_SCAN_BYTES,"sha256":hashlib.sha256(data).hexdigest(),"signature_count":len(sigs),"finding_count":len(findings),"highest_severity":highest,"findings":findings,"note":"Static pattern matching only. Matches can be false positives; no code was executed. Only the first 2 MiB are scanned."}
