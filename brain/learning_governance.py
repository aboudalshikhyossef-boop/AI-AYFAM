"""Governed learning from external AI providers.

External answers are evidence, not truth.  This module keeps an auditable record of
provider output and turns it into proposals that remain inert until a human review
and an explicit test result have both succeeded.  Code proposals are never applied
by this module; they can only be marked ready for a separate, reviewed merge.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from brain.context_engine import ContextEngine
from brain.weight_policy import WeightPolicy


class LearningGovernance:
    """Persistence and policy boundary for external learning."""

    def __init__(self, knowledge_base):
        self.kb = knowledge_base
        self.db_path = knowledge_base.db_path
        self.last_report = None
        self._init_schema()
        self.weight_policy = WeightPolicy(knowledge_base)

    def _conn(self):
        return self.kb._connect()

    def _init_schema(self):
        self._conn().executescript(
            """
            CREATE TABLE IF NOT EXISTS external_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                model TEXT,
                prompt TEXT NOT NULL,
                context TEXT NOT NULL DEFAULT '{}',
                answer TEXT NOT NULL,
                source TEXT NOT NULL,
                evaluation TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_external_provider
                ON external_interactions(provider, created_at);
            CREATE TABLE IF NOT EXISTS learning_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interaction_id INTEGER,
                kind TEXT NOT NULL CHECK(kind IN ('knowledge', 'code')),
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                payload TEXT NOT NULL DEFAULT '{}',
                risk TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'proposed',
                review_note TEXT,
                tests TEXT NOT NULL DEFAULT '{}',
                proposed_at TEXT NOT NULL DEFAULT (datetime('now')),
                reviewed_at TEXT,
                applied_at TEXT,
                FOREIGN KEY(interaction_id) REFERENCES external_interactions(id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_status
                ON learning_proposals(status, proposed_at);
            """
        )
        self._conn().commit()

    @staticmethod
    def _safe_text(value: Any, limit: int = 12000) -> str:
        return str(value or "").strip()[:limit]

    @staticmethod
    def _sanitize_external_text(value: Any, limit: int = 12000) -> str:
        """Remove local identifiers, filesystem paths, and recognizable API secrets."""
        text = ContextEngine.sanitize_privacy_data(str(value or ""))
        text = re.sub(r"(?i)\\bBearer\\s+[A-Za-z0-9._~+/-]{8,}={0,2}", "Bearer [REDACTED]", text)
        text = re.sub(r"\\bsk-[A-Za-z0-9_-]{12,}\\b", "[API_KEY]", text)
        text = re.sub(r"\\bAIza[0-9A-Za-z_-]{20,}\\b", "[API_KEY]", text)
        text = re.sub(
            r"(?i)\\b(?:OPENAI_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY)\\s*[:=]\\s*[^\\s,;]+",
            "[API_KEY_ASSIGNMENT]",
            text,
        )
        text = re.sub(r"(?<![A-Za-z0-9])/(?:home|root)/[^\\s,;)]*", "[LOCAL_PATH]", text)
        return text.strip()[:limit]

    @classmethod
    def _sanitize_context(cls, value: Any) -> Any:
        """Recursively scrub strings in audit context without changing scalar types."""
        if isinstance(value, str):
            return cls._sanitize_external_text(value, 2000)
        if isinstance(value, Mapping):
            return {
                cls._sanitize_external_text(key, 160): cls._sanitize_context(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [cls._sanitize_context(item) for item in value]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return cls._sanitize_external_text(value, 2000)

    @staticmethod
    def evaluate_answer(prompt: str, answer: str) -> dict:
        """Conservative, explainable screening; it does not establish truth."""
        text = LearningGovernance._safe_text(answer)
        lower = text.lower()
        flags = []
        if len(text) < 40:
            flags.append("too_short")
        if any(token in lower for token in ("i am certain", "مؤكد تماماً", "guaranteed", "مضمون")):
            flags.append("overconfident_language")
        if any(token in lower for token in ("run this", "نفذ الأمر", "curl | sh", "rm -rf")):
            flags.append("actionable_command_requires_review")
        if not any(token in lower for token in ("evidence", "دليل", "confidence", "ثقة", "limitation", "حدود")):
            flags.append("missing_limitations")
        score = max(0.0, min(1.0, 0.8 - 0.15 * len(flags)))
        style = LearningGovernance.extract_style_features(text)
        return {
            "screening_score": round(score, 2),
            "flags": flags,
            "review_required": True,
            "answer_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "style_features": style,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def extract_style_features(answer: str) -> dict:
        """Extract reusable response behavior, never facts or verbatim text."""
        text = LearningGovernance._safe_text(answer)
        sentences = [s for s in re.split(r"[.!؟?\n]+", text) if s.strip()]
        words = re.findall(r"[\w\u0600-\u06FF]+", text, flags=re.UNICODE)
        bullets = len(re.findall(r"(?m)^\s*(?:[-*•]|\d+[.)])\s+", text))
        evidence = len(re.findall(r"evidence|دليل|سبب|because|لأن|استناد", text, re.I))
        caution = len(re.findall(r"حدود|تحقق|مراجعة|احتمال|قد |لا يمكن الجزم|limitation|verify|review", text, re.I))
        steps = len(re.findall(r"(?m)^\s*\d+[.)]\s+|first|then|أولاً|ثم|بعد ذلك", text, re.I))
        return {
            "structured": round(min(1.0, bullets / max(1, len(sentences))), 3),
            "evidence": round(min(1.0, evidence / max(1, len(sentences))), 3),
            "caution": round(min(1.0, caution / max(1, len(sentences))), 3),
            "steps": round(min(1.0, steps / max(1, len(sentences))), 3),
            "avg_sentence_words": round(len(words) / max(1, len(sentences)), 1),
        }

    def get_style_profile(self) -> dict:
        """Return aggregate style weights; only approved-safe style metadata is used."""
        rows = self._conn().execute("SELECT evaluation FROM external_interactions ORDER BY id DESC LIMIT 100").fetchall()
        profiles = []
        for row in rows:
            try:
                style = json.loads(row["evaluation"]).get("style_features", {})
                if style:
                    profiles.append(style)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        if not profiles:
            return {"structured": 0.5, "evidence": 0.7, "caution": 0.7, "steps": 0.3, "avg_sentence_words": 18.0}
        keys = ("structured", "evidence", "caution", "steps", "avg_sentence_words")
        return {key: round(sum(float(p.get(key, 0.0)) for p in profiles) / len(profiles), 3) for key in keys}

    def record_external_answer(self, *, provider: str, model: str, prompt: str,
                               context: Mapping[str, Any] | None, answer: str,
                               source: str | None = None) -> int:
        """Store a provider answer and its provenance without trusting it."""
        prompt = self._sanitize_external_text(prompt)
        answer = self._sanitize_external_text(answer)
        source = self._sanitize_external_text(source or f"provider:{provider}", 300)
        safe_context = self._sanitize_context(dict(context or {}))
        context_json = json.dumps(safe_context, ensure_ascii=False, sort_keys=True)
        evaluation = self.evaluate_answer(prompt, answer)
        cur = self._conn().execute(
            "INSERT INTO external_interactions(provider, model, prompt, context, answer, source, evaluation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self._safe_text(provider, 80), self._safe_text(model, 160), prompt,
             context_json, answer, source, json.dumps(evaluation, ensure_ascii=False)),
        )
        self._conn().commit()
        interaction_id = int(cur.lastrowid)
        # Create a quarantined knowledge candidate; nothing is inserted into knowledge.
        knowledge_proposal_id = self.create_knowledge_proposal(
            title=f"External answer from {provider}",
            description="Candidate knowledge extracted from an external answer; review evidence before accepting.",
            content=answer,
            category="external_candidate",
            key=f"external-{interaction_id}",
            interaction_id=interaction_id,
            risk="high" if evaluation["flags"] else "medium",
        )
        # Generate a calculated local-policy candidate from observable style only.
        # The candidate is versioned and remains proposed until separately reviewed.
        weight_profile_id = self.weight_policy.propose_from_observation(
            evaluation.get("style_features", {}), interaction_id=interaction_id
        )
        self.last_report = {
            "mode": "external",
            "interaction_id": interaction_id,
            "saved": True,
            "knowledge_proposal_id": knowledge_proposal_id,
            "weight_profile_id": weight_profile_id,
            "screening_score": evaluation["screening_score"],
            "flags": evaluation["flags"],
            "knowledge_status": "quarantined",
            "weight_status": "proposed_not_active",
            "learned_facts": 0,
            "inferences": 0,
        }
        return interaction_id

    def local_learning_report(self, question: str) -> dict:
        """Report measurable local evidence used for a response."""
        active = self.weight_policy.active()
        matches = self.kb.search_knowledge(question, limit=5)
        return {
            "mode": "local",
            "saved": False,
            "question": question,
            "evidence_count": len(matches),
            "evidence_keys": [item.get("key", "") for item in matches],
            "active_weight_profile": active.get("name", "unknown"),
            "active_weight_id": active.get("id", 0),
            "learned_facts": sum(1 for item in matches if item.get("source") in ("user", "self_learned")),
            "inferences": 0,
        }

    def create_knowledge_proposal(self, *, title: str, description: str, content: str,
                                  category: str, key: str, interaction_id: int | None = None,
                                  risk: str = "medium") -> int:
        payload = {"category": category, "key": key, "content": self._safe_text(content)}
        cur = self._conn().execute(
            "INSERT INTO learning_proposals(interaction_id, kind, title, description, payload, risk) "
            "VALUES (?, 'knowledge', ?, ?, ?, ?)",
            (interaction_id, self._safe_text(title, 240), self._safe_text(description),
             json.dumps(payload, ensure_ascii=False), risk),
        )
        self._conn().commit()
        return int(cur.lastrowid)

    def create_code_proposal(self, *, title: str, description: str, patch: str,
                             tests: list[str], interaction_id: int | None = None,
                             risk: str = "high") -> int:
        """Create a code suggestion only; no file is changed and no command is run."""
        payload = {"patch": self._safe_text(patch, 50000), "tests": list(tests or [])}
        cur = self._conn().execute(
            "INSERT INTO learning_proposals(interaction_id, kind, title, description, payload, risk) "
            "VALUES (?, 'code', ?, ?, ?, ?)",
            (interaction_id, self._safe_text(title, 240), self._safe_text(description),
             json.dumps(payload, ensure_ascii=False), risk),
        )
        self._conn().commit()
        return int(cur.lastrowid)

    def list_proposals(self, status: str | None = None) -> list[dict]:
        query = "SELECT * FROM learning_proposals"
        params: tuple[Any, ...] = ()
        if status:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY id DESC"
        rows = self._conn().execute(query, params).fetchall()
        return [self._proposal(row) for row in rows]

    @staticmethod
    def _proposal(row) -> dict:
        return {"id": row["id"], "interaction_id": row["interaction_id"], "kind": row["kind"],
                "title": row["title"], "description": row["description"],
                "payload": json.loads(row["payload"]), "risk": row["risk"],
                "status": row["status"], "review_note": row["review_note"],
                "tests": json.loads(row["tests"]), "proposed_at": row["proposed_at"]}

    def review(self, proposal_id: int, *, approved: bool, note: str) -> bool:
        if not self._safe_text(note, 2000):
            raise ValueError("A review note is required")
        status = "reviewed" if approved else "rejected"
        cur = self._conn().execute(
            "UPDATE learning_proposals SET status=?, review_note=?, reviewed_at=datetime('now') "
            "WHERE id=? AND status='proposed'", (status, self._safe_text(note, 2000), proposal_id))
        self._conn().commit()
        return cur.rowcount == 1

    def record_test_result(self, proposal_id: int, *, passed: bool, command: str,
                           output: str = "") -> bool:
        """Record externally-run automated tests; commands are audit data, never executed here."""
        row = self._conn().execute("SELECT status FROM learning_proposals WHERE id=?", (proposal_id,)).fetchone()
        if not row or row["status"] not in ("reviewed", "tested"):
            return False
        tests = {"passed": bool(passed), "command": self._safe_text(command, 500),
                 "output": self._safe_text(output, 4000),
                 "recorded_at": datetime.now(timezone.utc).isoformat()}
        status = "tested" if passed else "reviewed"
        self._conn().execute("UPDATE learning_proposals SET tests=?, status=? WHERE id=?",
                             (json.dumps(tests, ensure_ascii=False), status, proposal_id))
        self._conn().commit()
        return True

    def apply(self, proposal_id: int) -> bool:
        """Apply only reviewed-and-tested knowledge; code proposals stay merge-only."""
        row = self._conn().execute("SELECT * FROM learning_proposals WHERE id=?", (proposal_id,)).fetchone()
        if not row or row["status"] != "tested":
            return False
        tests = json.loads(row["tests"])
        if not tests.get("passed"):
            return False
        if row["kind"] == "code":
            self._conn().execute("UPDATE learning_proposals SET status='ready_for_merge' WHERE id=?", (proposal_id,))
            self._conn().commit()
            return False
        payload = json.loads(row["payload"])
        self.kb.add_knowledge(payload["category"], payload["key"], payload["content"],
                              source=f"reviewed_external:{row['interaction_id'] or proposal_id}")
        self._conn().execute("UPDATE learning_proposals SET status='applied', applied_at=datetime('now') WHERE id=?",
                             (proposal_id,))
        self._conn().commit()
        return True
