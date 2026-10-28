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


def test_invalid_samples_per_intent(temp_kb):
    trainer = ParallelTrainer(kb=temp_kb)
    with pytest.raises(ValueError, match="samples_per_intent must be a non-negative integer"):
        trainer.generate_synthetic_dataset(samples_per_intent=-1)

    with pytest.raises(ValueError, match="samples_per_intent must be a non-negative integer"):
        trainer.generate_synthetic_dataset(samples_per_intent=True)

    with pytest.raises(ValueError, match="samples_per_intent must be a non-negative integer"):
        trainer.generate_synthetic_dataset(samples_per_intent="25")


def test_invalid_max_workers(temp_kb):
    trainer = ParallelTrainer(kb=temp_kb)
    with pytest.raises(ValueError, match="max_workers must be a positive integer"):
        trainer.run_benchmark(max_workers=0)

    with pytest.raises(ValueError, match="max_workers must be a positive integer"):
        trainer.run_benchmark(max_workers=-2)

    with pytest.raises(ValueError, match="max_workers must be a positive integer"):
        trainer.run_benchmark(max_workers=True)

    with pytest.raises(ValueError, match="max_workers must be a positive integer"):
        trainer.run_benchmark(max_workers="4")


def test_empty_dataset_handling(temp_kb):
    trainer = ParallelTrainer(kb=temp_kb)
    report = trainer.run_benchmark(dataset=[])
    assert isinstance(report, BenchmarkReport)
    assert report.total_samples == 0
    assert report.correct_matches == 0
    assert report.accuracy_percentage == 0.0
    assert report.average_response_ms == 0.0
    assert report.failures == []
