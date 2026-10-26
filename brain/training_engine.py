"""
AI AYFAM — Parallel & Stable Local Training Engine
محرك التدريب والتقييم المتوازي لجميع مكونات الذكاء المحلي.

يقوم بتقييم آلاف الأسئلة والطلبات والتوقعات وأنماط التعليم والإنذارات بصورة
متوازية، مستقرة، وآمنة خيطياً (thread-safe)، مع قياس الدقة وسرعة الاستجابة
وتوزيع أساليب الرد.
"""

from __future__ import annotations

import concurrent.futures
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from brain.conversation import ConversationEngine
from brain.knowledge_base import KnowledgeBase
from brain.language import analyze, find_misconceptions
from brain.learning import PhraseMemory, parse_teaching
from brain.nlp import NLPEngine


@dataclass
class EvaluationSample:
    query: str
    expected_intent: str | None = None
    expected_action: str | None = None
    expected_style: str | None = None
    is_teaching: bool = False
    is_misconception: bool = False
    category: str = "general"


@dataclass
class EvaluationResult:
    sample: EvaluationSample
    predicted_intent: str | None
    predicted_action: str
    predicted_style: str
    is_correct_intent: bool
    is_correct_action: bool
    latency_ms: float
    error: str | None = None


def generate_benchmark_dataset() -> List[EvaluationSample]:
    """توليد مجموعة بيانات ضخمة تفوق 1000 عينة متنوعة بالعربية والإنجليزي،
    تغطي كافة فئات الأمن السيبراني والأوامر والتعليم والمفاهيم الخاطئة."""
    samples: List[EvaluationSample] = []

    # 1) أنماط فحص الشبكة
    net_queries = [
        ("افحص الشبكة الان", "scan_network", "route", "brief_action", "network"),
        ("تحقق من الاتصالات النشطة والشبكة", "scan_network", "route", "brief_action", "network"),
        ("scan network connections", "scan_network", "route", "brief_action", "network"),
        ("افحص شبكتي المحلية", "scan_network", "route", "brief_action", "network"),
        ("هل يوجد جدار حماية يعمل؟", "check_firewall", "route", "brief_action", "network"),
        ("حالة ufw وجدار الحماية", "check_firewall", "route", "brief_action", "network"),
        ("check firewall status", "check_firewall", "route", "brief_action", "network"),
        ("افحص المنافذ المفتوحة 192.168.1.1", "scan_ports", "route", "brief_action", "network"),
        ("scan ports on host 10.0.0.1", "scan_ports", "route", "brief_action", "network"),
        ("منفذ 22 مفتوح", "scan_ports", "route", "brief_action", "network"),
        ("تحقق من سمعة IP 8.8.8.8", "check_ip", "route", "brief_action", "network"),
        ("check ip reputation 1.1.1.1", "check_ip", "route", "brief_action", "network"),
        ("حالة شبكة الواي فاي", "wifi", "route", "brief_action", "network"),
        ("check wifi networks", "wifi", "route", "brief_action", "network"),
    ]

    # 2) أنماط فحص النظام وسجلاته
    sys_queries = [
        ("افحص النظام بالكامل", "scan_system", "route", "brief_action", "system"),
        ("فحص ملفات SUID والعمليات", "scan_system", "route", "brief_action", "system"),
        ("full system security audit", "scan_system", "route", "brief_action", "system"),
        ("حلل سجلات النظام auth.log", "scan_logs", "route", "brief_action", "system"),
        ("scan system logs for brute force", "scan_logs", "route", "brief_action", "system"),
        ("تحليل سجلات الدخول", "scan_logs", "route", "brief_action", "system"),
        ("تحكم في أجهزة USB الفلاشة", "usb_control", "route", "brief_action", "usb"),
        ("check connected flash drive", "usb_control", "route", "brief_action", "usb"),
        ("افحص الفلاشة الموصولة", "usb_control", "route", "brief_action", "usb"),
    ]

    # 3) أنماط المواقع والثغرات وCVE
    vuln_queries = [
        ("افحص أمان موقع https://example.com", "scan_website", "route", "brief_action", "web_cve"),
        ("scan website security headers", "scan_website", "route", "brief_action", "web_cve"),
        ("ابحث عن ثغرة CVE-2024-3094", "cve_search", "route", "brief_action", "web_cve"),
        ("search CVE details CVE-2021-44228", "cve_search", "route", "brief_action", "web_cve"),
        ("ثغرات حزمة requests في PyPI", "pkg_vuln_search", "route", "brief_action", "web_cve"),
        ("package vulnerabilities django", "pkg_vuln_search", "route", "brief_action", "web_cve"),
    ]

    # 4) أنماط الشرح والمفاهيم الأمنية المعقدة
    explain_queries = [
        ("اشرح لي هجوم Brute Force وكيف أمنعه", "explain", "ai", "detailed_explanation", "explanation"),
        ("explain SQL injection with examples", "explain", "ai", "detailed_explanation", "explanation"),
        ("ما هو Metasploit وكيف يعمل", "explain", "ai", "detailed_explanation", "explanation"),
        ("ما معنى Man-in-the-Middle attack", "explain", "ai", "detailed_explanation", "explanation"),
        ("ما هو بروتوكول SSH وما المنفذ الخاص به", "explain", "ai", "detailed_explanation", "explanation"),
        ("كيف تعمل برمجيات الفدية Ransomware", "explain", "ai", "detailed_explanation", "explanation"),
        ("ما الفرق بين Symmetric و Asymmetric Encryption", "explain", "ai", "detailed_explanation", "explanation"),
    ]

    # 5) أنماط التعليم وتصحيح الكلمات
    teaching_queries = [
        ("عندما اقول سلام رد باهلا وسهلا", "teach", "reply", "brief_action", "teaching"),
        ("كلمة تمام تعني جيد جدا", "teach", "reply", "brief_action", "teaching"),
        ("انسى كلمة سلام", "teach", "reply", "brief_action", "teaching"),
        ("تعلم ان النواة هي قلب نظام التشغيل", "teach", "reply", "brief_action", "teaching"),
        ("remember that SSH uses port 22", "teach", "reply", "brief_action", "teaching"),
    ]

    # 6) المفاهيم الخاطئة
    misconception_queries = [
        ("الـ VPN يجعلني مجهول الهوية بالكامل 100%", "explain", "reply", "misconception_correction", "misconception"),
        ("نظام لينكس لا يصاب بالفيروسات مطلقا", "explain", "reply", "misconception_correction", "misconception"),
        ("توجد حماية 100% لا يمكن اختراقها", "explain", "reply", "misconception_correction", "misconception"),
        ("المنفذ المفتوح يعني ان الجهاز مخترق", "explain", "reply", "misconception_correction", "misconception"),
        ("التصفح الخفي يحميني من التتبع بالكامل", "explain", "reply", "misconception_correction", "misconception"),
    ]

    # جمع القوالب الأولية
    base_samples: List[Tuple[str, str, str, str, str]] = (
        net_queries + sys_queries + vuln_queries + explain_queries + teaching_queries + misconception_queries
    )

    # مضاعفة العينات مع تنويع الصياغات والأخطاء الإملائية الشائعة للتأكد من تجاوز 1000 عينة
    typo_prefixes = ["من فضلك ", "لو سمحت ", "اريد ان ", "هل يمكنك ", "رجاء ", ""]
    typo_suffixes = [" بسرعة", " الآن", " فوراً", " من فضلك", ""]

    sample_id = 0
    for q, intent, action, style, cat in base_samples:
        for prefix in typo_prefixes:
            for suffix in typo_suffixes:
                full_q = f"{prefix}{q}{suffix}".strip()
                is_teach = cat == "teaching"
                is_misc = cat == "misconception"
                samples.append(EvaluationSample(
                    query=full_q,
                    expected_intent=intent,
                    expected_action=action,
                    expected_style=style,
                    is_teaching=is_teach,
                    is_misconception=is_misc,
                    category=cat,
                ))
                sample_id += 1
                if len(samples) >= 1050:
                    break
            if len(samples) >= 1050:
                break
        if len(samples) >= 1050:
            break

    return samples


def _evaluate_single_sample(sample: EvaluationSample, db_dir: str) -> EvaluationResult:
    """تقييم عينة واحدة في خيط مستقل مع قاعدة بيانات معزولة لمنع التعارض."""
    start_time = time.perf_counter()
    db_path = os.path.join(db_dir, f"test_{os.getpid()}_{id(sample)}.db")

    try:
        kb = KnowledgeBase(db_path=db_path)
        nlp = NLPEngine(knowledge_base=kb)
        phrases = PhraseMemory(kb)
        engine = ConversationEngine(kb, nlp, phrases)

        # تنفيذ معالجة الطلب
        turn = engine.process(sample.query)
        cmd = turn.cmd or nlp.parse(turn.text)

        pred_intent = cmd.intent if cmd else None
        pred_action = turn.action
        pred_style = getattr(turn, "style", "brief_action")

        is_correct_intent = (sample.expected_intent is None) or (pred_intent == sample.expected_intent)
        is_correct_action = (sample.expected_action is None) or (pred_action == sample.expected_action)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return EvaluationResult(
            sample=sample,
            predicted_intent=pred_intent,
            predicted_action=pred_action,
            predicted_style=pred_style,
            is_correct_intent=is_correct_intent,
            is_correct_action=is_correct_action,
            latency_ms=elapsed_ms,
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return EvaluationResult(
            sample=sample,
            predicted_intent=None,
            predicted_action="error",
            predicted_style="error",
            is_correct_intent=False,
            is_correct_action=False,
            latency_ms=elapsed_ms,
            error=str(exc),
        )
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


class ParallelTrainer:
    """مدرب ومقيّم الذكاء المحلي المتوازي"""

    def __init__(self, max_workers: int = 8):
        self.max_workers = max_workers

    def run_training_suite(self, samples: List[EvaluationSample] | None = None) -> Dict[str, Any]:
        """تشغيل مجموعة التقييم المتوازية لحساب المقاييس الإحصائية والاستقرار."""
        if samples is None:
            samples = generate_benchmark_dataset()

        start_all = time.perf_counter()
        results: List[EvaluationResult] = []

        with tempfile.TemporaryDirectory() as tmp_dir:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [
                    executor.submit(_evaluate_single_sample, sample, tmp_dir)
                    for sample in samples
                ]
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())

        total_time = time.perf_counter() - start_all

        # حساب الإحصائيات
        total_count = len(results)
        intent_matches = sum(1 for r in results if r.is_correct_intent)
        action_matches = sum(1 for r in results if r.is_correct_action)
        errors_count = sum(1 for r in results if r.error is not None)
        avg_latency = sum(r.latency_ms for r in results) / total_count if total_count else 0.0

        intent_accuracy = (intent_matches / total_count * 100.0) if total_count else 0.0
        action_accuracy = (action_matches / total_count * 100.0) if total_count else 0.0

        # أداء الفئات
        category_stats: Dict[str, Dict[str, float]] = {}
        by_cat: Dict[str, List[EvaluationResult]] = {}
        for r in results:
            by_cat.setdefault(r.sample.category, []).append(r)

        for cat, cat_results in by_cat.items():
            cat_total = len(cat_results)
            cat_intent_ok = sum(1 for cr in cat_results if cr.is_correct_intent)
            category_stats[cat] = {
                "total": cat_total,
                "intent_accuracy": (cat_intent_ok / cat_total * 100.0) if cat_total else 0.0,
                "avg_latency_ms": sum(cr.latency_ms for cr in cat_results) / cat_total if cat_total else 0.0,
            }

        return {
            "total_samples": total_count,
            "total_time_sec": total_time,
            "throughput_qps": total_count / total_time if total_time > 0 else 0.0,
            "intent_accuracy_pct": intent_accuracy,
            "action_accuracy_pct": action_accuracy,
            "avg_latency_ms": avg_latency,
            "errors_count": errors_count,
            "category_stats": category_stats,
        }
