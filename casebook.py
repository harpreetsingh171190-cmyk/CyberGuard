"""Small local JSON casebook for analyst triage; no network access."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

CASEBOOK_PATH = Path(os.getenv('CYBERGUARD_CASEBOOK_PATH', 'cyberguard_cases.json'))
STATUSES = {'New', 'Investigating', 'Contained', 'Closed', 'False positive'}
SEVERITIES = {'Low', 'Medium', 'High', 'Critical'}


def load_cases(path=CASEBOOK_PATH):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_cases(cases, path=CASEBOOK_PATH):
    Path(path).write_text(json.dumps(cases, indent=2, ensure_ascii=False), encoding='utf-8')


def create_case(title, severity='Medium', indicators=None, notes='', path=CASEBOOK_PATH):
    title = str(title).strip()
    if not title:
        raise ValueError('Case title is required.')
    if severity not in SEVERITIES:
        raise ValueError('Unsupported severity.')
    cases = load_cases(path)
    case = {
        'case_id': f"CG-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{len(cases)+1:03d}",
        'title': title[:160], 'severity': severity, 'status': 'New',
        'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'updated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'indicators': list(dict.fromkeys(str(x).strip() for x in (indicators or []) if str(x).strip())),
        'notes': str(notes)[:10000], 'timeline': [{'at': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'event': 'Case created'}]
    }
    cases.append(case)
    save_cases(cases, path)
    return case


def update_case(case_id, status=None, severity=None, notes=None, path=CASEBOOK_PATH):
    cases = load_cases(path)
    for case in cases:
        if case.get('case_id') != case_id:
            continue
        if status is not None and status not in STATUSES:
            raise ValueError('Unsupported status.')
        if severity is not None and severity not in SEVERITIES:
            raise ValueError('Unsupported severity.')
        events = []
        if status is not None and status != case.get('status'):
            case['status'] = status; events.append(f'Status changed to {status}')
        if severity is not None and severity != case.get('severity'):
            case['severity'] = severity; events.append(f'Severity changed to {severity}')
        if notes is not None:
            case['notes'] = str(notes)[:10000]
            events.append('Analyst notes updated')
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        case['updated_at'] = now
        case.setdefault('timeline', []).extend({'at': now, 'event': event} for event in events)
        save_cases(cases, path)
        return case
    raise KeyError(f'Case not found: {case_id}')


def delete_case(case_id, path=CASEBOOK_PATH):
    cases = load_cases(path)
    remaining = [c for c in cases if c.get('case_id') != case_id]
    if len(remaining) == len(cases):
        raise KeyError(f'Case not found: {case_id}')
    save_cases(remaining, path)
