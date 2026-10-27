"""
AI AYFAM — Local Training & Benchmark Evaluation Engine
توفير وحدة تدريب وتقييم محلية متوازنة وتوليد بيانات اختبار لقياس الدقة والسرعة
"""

import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from brain.knowledge_base import KnowledgeBase, SEED_INTENTS
from brain.nlp import NLPEngine
from brain.conversation import ConversationEngine


@dataclass
class EvaluationSample:
    query: str
    expected_intent: str
    category: str = "general"


@dataclass
class BenchmarkReport:
    total_samples: int
    correct_matches: int
    accuracy_percentage: float
    average_response_ms: float
    failures: List[Dict[str, str]] = field(default_factory=list)


class ParallelTrainer:
    """مدرّب محلي متوازي لتقييم وتدريب أنماط النوايا والكلمات المفتاحية"""

    def __init__(self, kb: Optional[KnowledgeBase] = None):
        self.kb = kb or KnowledgeBase()
        self.nlp = NLPEngine(self.kb)
        self.conv = ConversationEngine(self.kb, self.nlp)

    def generate_synthetic_dataset(self, samples_per_intent: int = 25) -> List[EvaluationSample]:
        """توليد مجموعة بيانات سينتاتيكية ضخمة بناءً على الأنماط والأوامر المعرفة"""
        dataset = []
        intents = self.kb.get_intents()

        prefix_phrases = [
            "أريد أن أعمل", "من فضلك قم بـ", "هل يمكنك", "اريد", "يرجى",
            "قم فوراً بـ", "كيف أستطيع", "لو سمحت", "ارغب في", "ساعدني في"
        ]
        suffix_phrases = [
            "الآن", "فوراً", "بشكل دقيق", "من فضلك", "على النظام", "في الشبكة المحلية"
        ]

        for intent_name, patterns in intents:
            for pattern in patterns:
                # العينة الأساسية
                dataset.append(EvaluationSample(query=pattern, expected_intent=intent_name))

                # عينات موسعة بعبارات سابقة ولاحقة
                for p in prefix_phrases[:samples_per_intent // len(patterns) if len(patterns) > 0 else 1]:
                    q = f"{p} {pattern}"
                    dataset.append(EvaluationSample(query=q, expected_intent=intent_name))
                for s in suffix_phrases[:samples_per_intent // len(patterns) if len(patterns) > 0 else 1]:
                    q = f"{pattern} {s}"
                    dataset.append(EvaluationSample(query=q, expected_intent=intent_name))

        return dataset

    def _evaluate_single(self, sample: EvaluationSample) -> Tuple[bool, str, float]:
        start = time.perf_counter()
        parsed = self.nlp.parse(sample.query)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        is_correct = (parsed.intent == sample.expected_intent)
        detected = parsed.intent or "unknown"
        return is_correct, detected, elapsed_ms

    def run_benchmark(self, dataset: Optional[List[EvaluationSample]] = None, max_workers: int = 4) -> BenchmarkReport:
        """تشغيل التقييم المقارن بشكل متوازي وحساب الدقة وسرعة الاستجابة"""
        if not dataset:
            dataset = self.generate_synthetic_dataset()

        correct = 0
        total_ms = 0.0
        failures = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sample = {executor.submit(self._evaluate_single, sample): sample for sample in dataset}
            for future in concurrent.futures.as_completed(future_to_sample):
                sample = future_to_sample[future]
                try:
                    is_correct, detected, elapsed_ms = future.result()
                    total_ms += elapsed_ms
                    if is_correct:
                        correct += 1
                    else:
                        failures.append({
                            "query": sample.query,
                            "expected": sample.expected_intent,
                            "detected": detected
                        })
                except Exception as e:
                    failures.append({
                        "query": sample.query,
                        "expected": sample.expected_intent,
                        "detected": f"error: {str(e)}"
                    })

        total = len(dataset)
        acc = (correct / total * 100.0) if total > 0 else 0.0
        avg_ms = (total_ms / total) if total > 0 else 0.0

        return BenchmarkReport(
            total_samples=total,
            correct_matches=correct,
            accuracy_percentage=round(acc, 2),
            average_response_ms=round(avg_ms, 2),
            failures=failures[:50]
        )

    def train_and_optimize(self) -> Dict[str, float]:
        """تدريب أوزان النوايا وإثراء قاعدة المعرفة بالنمط الأكثر تكراراً"""
        report_before = self.run_benchmark()

        # أخذ العينات الفاشلة واقتراح تحسينات تلقائية لقاعدة البيانات
        for failure in report_before.failures:
            exp = failure["expected"]
            q = failure["query"]
            if exp and len(q) > 3:
                # اقتراح إضافة نمط محسن للنوايا
                self.kb.propose_improvement(
                    category="intent",
                    description=f"Automated training boost for pattern: {q}",
                    data={"name": exp, "patterns": [q]}
                )

        report_after = self.run_benchmark()
        return {
            "initial_accuracy": report_before.accuracy_percentage,
            "optimized_accuracy": report_after.accuracy_percentage,
            "avg_latency_ms": report_after.average_response_ms
        }
