"""
AI AYFAM — Incident Timeline Engine
محرك مخطط تسلسل الحوادث — يدمج الأحداث والنتائج الأمني في جدول زمني موحد
"""

import time
from typing import List, Dict, Any, Optional
from engine.finding import Finding
from engine.events import EventStore

class IncidentTimeline:
    """محرك بناء الجدول الزمني للحوادث الأمنية."""

    def __init__(self, store: Optional[EventStore] = None):
        self.store = store or EventStore()

    def build_timeline(self, findings: List[Finding], limit: int = 100) -> List[Dict[str, Any]]:
        timeline = []

        # 1. Add persistent events from store
        events = self.store.query_recent_events(limit=limit)
        for ev in events:
            timeline.append({
                "timestamp": ev["wall_time"],
                "item_type": "event",
                "source": ev["source"],
                "title": f"[{ev['severity'].upper()}] {ev['event_type']}: {ev['subject']}",
                "detail": ev["details"],
                "severity": ev["severity"],
                "fingerprint": ev["fingerprint"],
            })

        # 2. Add current findings
        now = time.time()
        for f in findings:
            timeline.append({
                "timestamp": f.get("timestamp", now),
                "item_type": "finding",
                "source": f.get("category", "finding"),
                "title": f"[{f.get('severity', 'info').upper()}] {f.get('title', '')}",
                "detail": f.get("detail", ""),
                "severity": f.get("severity", "info"),
                "fingerprint": f.get("fingerprint", f.id),
            })

        # Sort combined timeline chronologically
        timeline.sort(key=lambda x: x["timestamp"], reverse=True)
        return timeline[:limit]
