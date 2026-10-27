"""
Tests for local AI training engine and benchmark evaluator in brain/training_engine.py
"""

import pytest
import tempfile
from pathlib import Path
from brain.knowledge_base import KnowledgeBase
from brain.training_engine import ParallelTrainer, BenchmarkReport


@pytest.fixture
def temp_kb():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_brain.db"
        kb = KnowledgeBase(db_path=db_path)
        yield kb


def test_synthetic_dataset_generation(temp_kb):
    trainer = ParallelTrainer(kb=temp_kb)
    dataset = trainer.generate_synthetic_dataset(samples_per_intent=10)
    assert len(dataset) > 50
    assert any(s.expected_intent == "scan_network" for s in dataset)
    assert any(s.expected_intent == "scan_system" for s in dataset)


def test_run_benchmark_execution(temp_kb):
    trainer = ParallelTrainer(kb=temp_kb)
    report = trainer.run_benchmark(max_workers=2)
    assert isinstance(report, BenchmarkReport)
    assert report.total_samples > 0
    assert report.correct_matches > 0
    assert report.accuracy_percentage > 50.0
    assert report.average_response_ms >= 0.0


def test_train_and_optimize(temp_kb):
    trainer = ParallelTrainer(kb=temp_kb)
    results = trainer.train_and_optimize()
    assert "initial_accuracy" in results
    assert "optimized_accuracy" in results
    assert "avg_latency_ms" in results
    assert results["initial_accuracy"] > 0.0
اختبارات محرك التدريب والتقييم المتوازي (brain/training_engine.py)
"""

import unittest
from brain.training_engine import (
    generate_benchmark_dataset,
    ParallelTrainer,
    EvaluationSample,
)


class TestTrainingEngine(unittest.TestCase):
    def test_benchmark_dataset_generation(self):
        samples = generate_benchmark_dataset()
        self.assertGreaterEqual(len(samples), 1000)
        first = samples[0]
        self.assertIsInstance(first, EvaluationSample)
        self.assertTrue(len(first.query) > 0)

    def test_parallel_trainer_execution(self):
        # تشغيل تقييم متوازي لدرجة أمان واستقرار مع عينة صغرى للتأكد من السرعة أثناء unittest
        samples = generate_benchmark_dataset()[:20]
        trainer = ParallelTrainer(max_workers=4)
        results = trainer.run_training_suite(samples)

        self.assertEqual(results["total_samples"], 20)
        self.assertGreaterEqual(results["throughput_qps"], 0.0)
        self.assertGreaterEqual(results["intent_accuracy_pct"], 0.0)
        self.assertEqual(results["errors_count"], 0)


if __name__ == "__main__":
    unittest.main()
