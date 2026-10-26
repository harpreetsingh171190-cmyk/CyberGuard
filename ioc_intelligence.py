"""Offline IOC clustering and portable STIX 2.1 export helpers."""
from datetime import datetime, timezone
from urllib.parse import urlsplit
import uuid


def _domain_group(host: str) -> str:
    """A deliberately simple grouping key; not a public-suffix implementation."""
    host = (host or '').lower().rstrip('.')
    if not host:
        return '(unknown host)'
    if ':' in host or host.replace('.', '').isdigit():
        return host
    labels = host.split('.')
    return '.'.join(labels[-2:]) if len(labels) >= 2 else host


def cluster_indicators(indicators):
    """Group URLs by hostname/domain key and return useful offline summaries."""
    groups = {}
    for item in indicators or []:
        value = item.get('value', '')
        host = (urlsplit(value).hostname or '').lower().rstrip('.')
        key = _domain_group(host)
        group = groups.setdefault(key, {'group': key, 'count': 0, 'hosts': set(), 'urls': [], 'max_risk': 0})
        group['count'] += 1
        if host:
            group['hosts'].add(host)
        group['urls'].append(value)
        try:
            group['max_risk'] = max(group['max_risk'], int(item.get('heuristic_score', 0)))
        except (TypeError, ValueError):
            pass
    result = []
    for key, group in sorted(groups.items(), key=lambda pair: (-pair[1]['count'], pair[0])):
        result.append({**group, 'hosts': sorted(group['hosts'])})
    return result


def to_stix_bundle(indicators):
    """Create a minimal STIX 2.1 bundle of URL indicators (not threat verdicts)."""
    now = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    objects = []
    for item in indicators or []:
        value = str(item.get('value', '')).strip()
        if not value:
            continue
        # STIX single-quoted pattern literal escaping.
        escaped = value.replace('\\', '\\\\').replace("'", "\\'")
        objects.append({
            'type': 'indicator',
            'spec_version': '2.1',
            'id': f"indicator--{uuid.uuid4()}",
            'created': now,
            'modified': now,
            'name': 'CyberGuard URL indicator',
            'description': 'Extracted URL indicator for triage; this object does not assert maliciousness.',
            'pattern': f"[url:value = '{escaped}']",
            'pattern_type': 'stix',
            'valid_from': now,
            'labels': ['malicious-activity'] if str(item.get('heuristic_level', '')).lower() == 'high' else ['anomalous-activity'],
            'external_references': [{'source_name': 'CyberGuard', 'description': f"Offline heuristic score: {item.get('heuristic_score', 'unknown')} (not a verdict)"}]
        })
    return {'type': 'bundle', 'id': f'bundle--{uuid.uuid4()}', 'objects': objects}
