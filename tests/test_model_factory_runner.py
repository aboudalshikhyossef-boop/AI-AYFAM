"""Integration tests for the shared local model-training runner."""

import json

import pytest

pytest.importorskip("torch")

from model_factory.config import ModelConfig
from model_factory.corpus_tools import prepare_corpus
from model_factory.hardware import HardwareProfile
from model_factory.runner import TrainingRunConfig, run_training


def _prepared_corpus(tmp_path):
    raw_path = tmp_path / "raw.jsonl"
    prepared_path = tmp_path / "prepared.jsonl"
    rows = [
        {
            "text": ("نص عربي للتدريب المحلي في مشروع AYFAM. " * 100),
            "source": "runner-test-train",
            "license": "CC0-1.0",
            "split": "train",
            "group_id": "train-document",
        },
        {
            "text": "نص تحقق مستقل لقياس خسارة النموذج بعد التدريب.",
            "source": "runner-test-validation",
            "license": "CC0-1.0",
            "split": "validation",
            "group_id": "validation-document",
        },
        {
            "text": "نص اختبار منفصل لا يدخل في تحديث الأوزان.",
            "source": "runner-test-test",
            "license": "CC0-1.0",
            "split": "test",
            "group_id": "test-document",
        },
    ]
    raw_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    prepare_corpus(raw_path, prepared_path, require_held_out=True)
    return prepared_path


def test_runner_learns_bpe_trains_saves_and_evaluates_locally(tmp_path):
    corpus = _prepared_corpus(tmp_path)
    checkpoint = tmp_path / "private-run" / "latest.pt"
    tokenizer_path = tmp_path / "private-run" / "tokenizer.json"
    model_config = ModelConfig(
        vocab_size=260,
        block_size=8,
        n_layer=1,
        n_head=2,
        n_embd=16,
        ffn_dim=32,
        dropout=0.0,
    )
    observed_steps = []
    phases = []
    profile = HardwareProfile(8_000, 3_000, 2, "x86_64", "test")

    result = run_training(
        TrainingRunConfig(
            corpus_path=corpus,
            checkpoint_path=checkpoint,
            max_steps=1,
            device="cpu",
            tokenizer_mode="bpe",
            tokenizer_vocab_size=260,
            tokenizer_output_path=tokenizer_path,
            model_config=model_config,
        ),
        on_step=observed_steps.append,
        on_phase=phases.append,
        hardware_profile=profile,
    )

    assert checkpoint.is_file()
    assert tokenizer_path.is_file()
    assert result.completed_steps == 1
    assert not result.stopped_early
    from model_factory.architecture import AYFAMTransformer
    assert result.model_parameters == AYFAMTransformer(model_config).parameter_count()
    assert result.tokenizer_path == str(tokenizer_path)
    assert result.validation is not None
    assert result.validation["loss"] > 0
    assert len(observed_steps) == 1
    assert observed_steps[0].step == 1
    assert phases == [
        "validating_corpus",
        "preparing_tokenizer",
        "training",
        "evaluating",
        "completed",
    ]


def test_runner_config_rejects_invalid_training_options(tmp_path):
    with pytest.raises(ValueError, match="max_steps"):
        TrainingRunConfig(corpus_path=tmp_path / "corpus.jsonl", checkpoint_path=tmp_path / "latest.pt", max_steps=0)
    with pytest.raises(ValueError, match="tokenizer_mode"):
        TrainingRunConfig(
            corpus_path=tmp_path / "corpus.jsonl",
            checkpoint_path=tmp_path / "latest.pt",
            tokenizer_mode="external",
        )
