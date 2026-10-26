"""Safe static file triage. Never executes, extracts, or opens submitted files."""
from __future__ import annotations
import hashlib
import math
from collections import Counter
from pathlib import Path

MAGIC = [
    (b"MZ", "Windows PE executable", {".exe", ".dll", ".sys", ".scr"}),
    (b"\x7fELF", "ELF executable", {".elf", ".so", ".bin"}),
    (b"%PDF-", "PDF document", {".pdf"}),
    (b"PK\x03\x04", "ZIP-based archive/document", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
    (b"\x1f\x8b", "GZIP archive", {".gz", ".tgz"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"GIF87a", "GIF image", {".gif"}), (b"GIF89a", "GIF image", {".gif"}),
    (b"Rar!\x1a\x07", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
]


def _entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data); n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())


def analyze_file_bytes(filename: str, data: bytes) -> dict:
    """Analyze in-memory bytes only; reports clues, not a malware verdict."""
    name = Path(str(filename).replace('\\', '/')).name[:255] or "unnamed"
    raw = bytes(data)
    ext = Path(name).suffix.lower()
    matches = [(label, exts) for magic, label, exts in MAGIC if raw.startswith(magic)]
    detected = matches[0][0] if matches else ("Text-like / unknown format" if raw and b"\x00" not in raw[:4096] else "Unknown binary format")
    expected = matches[0][1] if matches else set()
    findings = []
    if matches and ext not in expected:
        findings.append({"severity": "high", "code": "EXTENSION_MISMATCH", "detail": f"File signature suggests {detected}, but extension is {ext or '(none)'}; expected one of {', '.join(sorted(expected))}."})
    if len(raw) == 0:
        findings.append({"severity": "low", "code": "EMPTY_FILE", "detail": "File is empty; analysis is limited."})
    if len(raw) > 100 * 1024 * 1024:
        findings.append({"severity": "medium", "code": "LARGE_FILE", "detail": "File exceeds 100 MiB; handle cautiously."})
    ent = round(_entropy(raw[:1024 * 1024]), 3)
    if len(raw) >= 4096 and ent >= 7.2:
        findings.append({"severity": "medium", "code": "HIGH_ENTROPY", "detail": "First MiB has high byte entropy; compression/encryption can also cause this."})
    double_exts = {".exe", ".scr", ".js", ".vbs", ".hta", ".bat", ".cmd", ".ps1", ".com", ".dll"}
    parts = Path(name).suffixes
    if len(parts) >= 2 and parts[-1].lower() in {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx", ".txt"} and any(x.lower() in double_exts for x in parts[:-1]):
        findings.append({"severity": "high", "code": "DOUBLE_EXTENSION", "detail": "Filename combines an executable/script-like extension with a document/media extension."})
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    highest = max((f["severity"] for f in findings), key=lambda x: order[x], default="info")
    return {"filename": name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "detected_type": detected,
            "extension": ext or "(none)", "entropy_first_mib": ent, "finding_count": len(findings), "highest_severity": highest,
            "findings": findings, "note": "Static triage only. No code was executed and no content was uploaded to a reputation service. A clean result does not prove a file is safe."}
