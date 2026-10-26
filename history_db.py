"""Local SQLite history for CyberGuard. Stores submitted URLs; keep database private."""
import json, os, sqlite3
from datetime import datetime, timezone

DB_PATH = os.getenv("CYBERGUARD_DB_PATH", "cyberguard_history.sqlite3")

def _connect():
    con = sqlite3.connect(DB_PATH, timeout=5)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, scanned_at TEXT NOT NULL, url TEXT NOT NULL, verdict TEXT NOT NULL, providers_json TEXT NOT NULL, list_match TEXT NOT NULL DEFAULT '')")
    return con

def save_scan(result, list_match=""):
    with _connect() as con:
        cur = con.execute("INSERT INTO scans(scanned_at,url,verdict,providers_json,list_match) VALUES(?,?,?,?,?)", (datetime.now(timezone.utc).isoformat(timespec="seconds"), result.get("url", ""), result.get("verdict", "INCONCLUSIVE"), json.dumps(result.get("provider_results", [])), list_match))
        return cur.lastrowid

def load_history(limit=500):
    with _connect() as con:
        rows = con.execute("SELECT id,scanned_at,url,verdict,providers_json,list_match FROM scans ORDER BY id DESC LIMIT ?", (max(1,min(int(limit),5000)),)).fetchall()
    return [{"id":r[0],"scanned_at":r[1],"url":r[2],"verdict":r[3],"provider_results":json.loads(r[4]),"list_match":r[5]} for r in rows]

def clear_history():
    with _connect() as con: con.execute("DELETE FROM scans")
