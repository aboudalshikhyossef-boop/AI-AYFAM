"""Adaptive local response-policy weights.

These are transparent policy weights, not inaccessible neural-model parameters.
They control how the local engine prioritizes evidence, alignment, caution,
structure and reasoning.  New versions are proposed from observed external
response features, reviewed, tested and activated explicitly with rollback.
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Mapping


DEFAULT_WEIGHTS = {
    "question_alignment": 1.00,
    "evidence_first": 0.90,
    "source_attribution": 0.80,
    "stepwise_reasoning": 0.55,
    "structured_response": 0.60,
    "brevity": 0.45,
    "examples": 0.35,
    "limitations": 0.80,
    "retrieval_score_display": 0.88,
}

# Only dimensions consumed by the current local explanation path are retained.
OBSERVED_TO_WEIGHT = {
    "evidence": "evidence_first",
    "steps": "stepwise_reasoning",
    "structured": "structured_response",
}


class WeightPolicy:
    """Versioned, auditable policy weights stored beside the local brain."""

    def __init__(self, knowledge_base):
        self.kb = knowledge_base
        self._init_schema()
        self._ensure_default()

    def _conn(self):
        return self.kb._connect()

    def _init_schema(self):
        self._conn().executescript(
            """
            CREATE TABLE IF NOT EXISTS local_weight_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id INTEGER,
                name TEXT NOT NULL,
                weights TEXT NOT NULL,
                source_interaction_id INTEGER,
                status TEXT NOT NULL DEFAULT 'proposed',
                review_note TEXT,
                tests TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                activated_at TEXT,
                FOREIGN KEY(parent_id) REFERENCES local_weight_profiles(id)
            );
            CREATE INDEX IF NOT EXISTS idx_weight_status ON local_weight_profiles(status, id);
            """
        )
        self._conn().commit()

    def _ensure_default(self):
        row = self._conn().execute(
            "SELECT id FROM local_weight_profiles WHERE status='active' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            return
        self._conn().execute(
            "INSERT INTO local_weight_profiles(name, weights, status, review_note, activated_at) "
            "VALUES (?, ?, 'active', ?, datetime('now'))",
            ("balanced-v1", json.dumps(DEFAULT_WEIGHTS, sort_keys=True), "Built-in safe baseline"),
        )
        self._conn().commit()

    @staticmethod
    def _clean(weights: Mapping[str, float]) -> dict[str, float]:
        result = dict(DEFAULT_WEIGHTS)
        for key in result:
            try:
                value = float(weights.get(key, result[key]))
            except (TypeError, ValueError):
                value = result[key]
            if not math.isfinite(value):
                value = result[key]
            result[key] = round(max(0.0, min(1.5, value)), 4)
        return result

    def active(self) -> dict:
        row = self._conn().execute(
            "SELECT id, name, weights, parent_id, source_interaction_id, created_at "
            "FROM local_weight_profiles WHERE status='active' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return {"id": 0, "name": "balanced-v1", "weights": dict(DEFAULT_WEIGHTS)}
        return {"id": row["id"], "name": row["name"], "weights": self._clean(json.loads(row["weights"])),
                "parent_id": row["parent_id"], "source_interaction_id": row["source_interaction_id"],
                "created_at": row["created_at"]}

    def propose_from_observation(self, features: Mapping[str, float], *, interaction_id: int | None = None,
                                 learning_rate: float = 0.15) -> int:
        """Create a calculated candidate; it is never activated automatically."""
        parent = self.active()
        candidate = dict(parent["weights"])
        rate = max(0.01, min(0.35, float(learning_rate)))
        for observed, target in OBSERVED_TO_WEIGHT.items():
            if observed in features:
                try:
                    signal = max(0.0, min(1.0, float(features[observed])))
                    candidate[target] = candidate[target] * (1.0 - rate) + signal * rate
                except (TypeError, ValueError):
                    pass
        candidate = self._clean(candidate)
        name = f"policy-v{parent['id'] + 1}-from-interaction-{interaction_id or 'manual'}"
        cur = self._conn().execute(
            "INSERT INTO local_weight_profiles(parent_id, name, weights, source_interaction_id) VALUES (?, ?, ?, ?)",
            (parent["id"], name, json.dumps(candidate, sort_keys=True), interaction_id),
        )
        self._conn().commit()
        return int(cur.lastrowid)

    def list_profiles(self, status: str | None = None) -> list[dict]:
        query = "SELECT * FROM local_weight_profiles"
        params = ()
        if status:
            query += " WHERE status=?"
            params = (status,)
        query += " ORDER BY id DESC"
        rows = self._conn().execute(query, params).fetchall()
        return [{"id": row["id"], "parent_id": row["parent_id"], "name": row["name"],
                 "weights": self._clean(json.loads(row["weights"])), "source_interaction_id": row["source_interaction_id"],
                 "status": row["status"], "review_note": row["review_note"],
                 "tests": json.loads(row["tests"]), "created_at": row["created_at"]} for row in rows]

    def review(self, profile_id: int, *, approved: bool, note: str) -> bool:
        if not str(note or "").strip():
            raise ValueError("A review note is required")
        status = "reviewed" if approved else "rejected"
        cur = self._conn().execute(
            "UPDATE local_weight_profiles SET status=?, review_note=? WHERE id=? AND status='proposed'",
            (status, str(note).strip()[:2000], profile_id),
        )
        self._conn().commit()
        return cur.rowcount == 1

    def record_test_result(self, profile_id: int, *, passed: bool, command: str, output: str = "") -> bool:
        row = self._conn().execute("SELECT status FROM local_weight_profiles WHERE id=?", (profile_id,)).fetchone()
        if not row or row["status"] not in ("reviewed", "tested"):
            return False
        tests = {"passed": bool(passed), "command": str(command or "")[:500],
                 "output": str(output or "")[:4000],
                 "recorded_at": datetime.now(timezone.utc).isoformat()}
        self._conn().execute(
            "UPDATE local_weight_profiles SET status=?, tests=? WHERE id=?",
            ("tested" if passed else "reviewed", json.dumps(tests, ensure_ascii=False), profile_id),
        )
        self._conn().commit()
        return True

    def activate(self, profile_id: int) -> bool:
        row = self._conn().execute(
            "SELECT * FROM local_weight_profiles WHERE id=? AND status='tested'", (profile_id,)
        ).fetchone()
        if not row or not json.loads(row["tests"]).get("passed"):
            return False
        conn = self._conn()
        conn.execute("UPDATE local_weight_profiles SET status='archived' WHERE status='active'")
        conn.execute(
            "UPDATE local_weight_profiles SET status='active', activated_at=datetime('now') WHERE id=?",
            (profile_id,),
        )
        conn.commit()
        return True

    def rollback(self, profile_id: int) -> bool:
        target = self._conn().execute(
            "SELECT parent_id FROM local_weight_profiles WHERE id=? AND status='active'", (profile_id,)
        ).fetchone()
        if not target or not target["parent_id"]:
            return False
        conn = self._conn()
        conn.execute("UPDATE local_weight_profiles SET status='archived' WHERE id=?", (profile_id,))
        conn.execute("UPDATE local_weight_profiles SET status='active' WHERE id=?", (target["parent_id"],))
        conn.commit()
        return True
