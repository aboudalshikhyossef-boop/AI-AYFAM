"""
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
