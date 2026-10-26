"""Offline, self-contained HTML reports for CyberGuard investigations."""
from html import escape
from datetime import datetime, timezone


def build_case_report(case):
    """Return a print-friendly HTML report. All user-controlled values are escaped."""
    esc = lambda value: escape(str(value if value is not None else ""), quote=True)
    indicators = case.get("indicators", []) or []
    timeline = case.get("timeline", []) or []
    indicator_rows = "".join(f"<tr><td><code>{esc(item)}</code></td></tr>" for item in indicators)
    timeline_rows = "".join(
        f"<tr><td>{esc(item.get('at', ''))}</td><td>{esc(item.get('event', ''))}</td></tr>"
        for item in timeline if isinstance(item, dict)
    )
    if not indicator_rows:
        indicator_rows = '<tr><td>No indicators attached</td></tr>'
    if not timeline_rows:
        timeline_rows = '<tr><td colspan="2">No timeline events</td></tr>'
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberGuard Case {esc(case.get('case_id', ''))}</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#172033}}h1,h2{{color:#173b69}}.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.75rem}}.meta div{{background:#f2f5f9;padding:.8rem;border-radius:8px}}table{{width:100%;border-collapse:collapse;margin:1rem 0}}td,th{{border:1px solid #ccd4df;padding:.6rem;text-align:left;overflow-wrap:anywhere}}code{{white-space:pre-wrap;overflow-wrap:anywhere}}.notes{{white-space:pre-wrap;border:1px solid #ccd4df;padding:1rem;border-radius:8px}}@media print{{button{{display:none}}body{{margin:0;max-width:none}}}}</style></head><body>
<button onclick="window.print()">Print / Save as PDF</button><h1>CyberGuard Incident Report</h1>
<p>Generated {esc(generated)} · For analyst review; not a confirmed attribution or safety certification.</p>
<div class="meta"><div><b>Case ID</b><br>{esc(case.get('case_id'))}</div><div><b>Title</b><br>{esc(case.get('title'))}</div><div><b>Severity</b><br>{esc(case.get('severity'))}</div><div><b>Status</b><br>{esc(case.get('status'))}</div><div><b>Created</b><br>{esc(case.get('created_at'))}</div><div><b>Last updated</b><br>{esc(case.get('updated_at'))}</div></div>
<h2>Analyst notes</h2><div class="notes">{esc(case.get('notes', '')) or 'No notes recorded.'}</div>
<h2>Indicators ({len(indicators)})</h2><table><thead><tr><th>Indicator</th></tr></thead><tbody>{indicator_rows}</tbody></table>
<h2>Timeline</h2><table><thead><tr><th>Timestamp</th><th>Event</th></tr></thead><tbody>{timeline_rows}</tbody></table>
<footer><small>Keep this report private. It may contain sensitive URLs, investigation notes, and indicators.</small></footer></body></html>'''
