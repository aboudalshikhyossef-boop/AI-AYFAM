"""Tests for corpus-size and hardware-aware full-epoch planning."""

import json
import math

from model_factory.hardware import HardwareProfile, TrainingPlan
from model_factory.tokenizer import ByteTokenizer
from model_factory.workload import (
    count_training_workload,
    measure_train_data_bytes,
    recommend_tokenizer_vocab_size,
)


def _write_corpus(path):
    rows = [
        {
            "text": "AYFAM local training data. " * 13,
            "source": "train-a",
            "license": "owner permission",
            "split": "train",
        },
        {
            "text": "Second independent training passage. " * 7,
            "source": "train-b",
            "license": "owner permission",
            "split": "train",
        },
        {
            "text": "Validation only.",
            "source": "validation",
            "license": "owner permission",
            "split": "validation",
        },
        {
            "text": "Test only.",
            "source": "test",
            "license": "owner permission",
            "split": "test",
        },
    ]
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_workload_counts_all_train_blocks_and_exact_optimizer_steps_per_epoch(tmp_path):
    corpus = tmp_path / "prepared.jsonl"
    _write_corpus(corpus)
    tokenizer = ByteTokenizer()
    profile = HardwareProfile(8_000, 3_000, 2, "x86_64", "test")
    runtime = TrainingPlan(2, 4, 2, 25, 600, ("test profile",))

    result = count_training_workload(
        corpus,
        tokenizer,
        profile=profile,
        runtime_plan=runtime,
        block_size=16,
        epochs=3,
    )

    expected_blocks = 0
    expected_tokens = 0
    for text in ("AYFAM local training data. " * 13, "Second independent training passage. " * 7):
        token_count = len(tokenizer.encode(text, add_bos=True, add_eos=True))
        expected_tokens += token_count - 1
        expected_blocks += math.ceil((token_count - 1) / 16)
    expected_batches = math.ceil(expected_blocks / 2)
    expected_steps = math.ceil(expected_batches / 4)

    assert result.train_records == 2
    assert result.train_tokens == expected_tokens
    assert result.train_blocks_per_epoch == expected_blocks
    assert result.batches_per_epoch == expected_batches
    assert result.optimizer_steps_per_epoch == expected_steps
    assert result.additional_steps == expected_steps * 3


def test_vocabulary_target_responds_to_corpus_volume_and_available_memory():
    small_memory = HardwareProfile(8_000, 3_000, 2, "x86_64", "test")
    larger_memory = HardwareProfile(16_000, 10_000, 8, "x86_64", "test")

    small_target, _ = recommend_tokenizer_vocab_size(50_000, small_memory)
    book_target, _ = recommend_tokenizer_vocab_size(900_000, small_memory)
    large_target, _ = recommend_tokenizer_vocab_size(900_000, larger_memory)

    assert small_target == 320
    assert book_target == 512
    assert large_target == 768


def test_measure_train_data_bytes_ignores_held_out_splits(tmp_path):
    corpus = tmp_path / "prepared.jsonl"
    _write_corpus(corpus)
    records, byte_count = measure_train_data_bytes(corpus)

    assert records == 2
    assert byte_count == len(("AYFAM local training data. " * 13).encode("utf-8")) + len(
        ("Second independent training passage. " * 7).encode("utf-8")
    )
