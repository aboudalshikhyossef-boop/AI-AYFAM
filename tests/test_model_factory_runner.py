"""Integration tests for the shared local model-training runner."""

import json
from pathlib import Path

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
    assert (checkpoint.parent / "inference.pt").is_file()
    assert (checkpoint.parent / "active-model.json").is_file()
    assert result.completed_steps == 1
    assert result.requested_steps == 1
    assert not result.stopped_early
    from model_factory.architecture import AYFAMTransformer
    assert result.model_parameters == AYFAMTransformer(model_config).parameter_count()
    assert result.tokenizer_path == str(tokenizer_path)
    assert result.validation_before is not None
    assert result.validation is not None
    assert result.validation["loss"] > 0
    assert result.test_before is not None
    assert result.test is not None
    assert result.train_records == 1
    assert result.train_blocks_per_epoch > 0
    assert result.optimizer_steps_per_epoch > 0
    assert result.tokenizer_vocab_size == 260
    assert len(observed_steps) == 1
    assert observed_steps[0].step == 1
    assert phases == [
        "validating_corpus",
        "preparing_tokenizer",
        "evaluating_before",
        "training",
        "evaluating_after",
        "exporting_model",
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



def test_runner_auto_steps_cover_every_train_block_for_each_epoch(tmp_path):
    corpus = _prepared_corpus(tmp_path)
    checkpoint = tmp_path / "auto-run" / "latest.pt"
    tokenizer_path = tmp_path / "auto-run" / "tokenizer.json"
    model_config = ModelConfig(
        vocab_size=260,
        block_size=32,
        n_layer=1,
        n_head=2,
        n_embd=16,
        ffn_dim=32,
        dropout=0.0,
    )
    profile = HardwareProfile(8_000, 3_000, 2, "x86_64", "test")

    result = run_training(
        TrainingRunConfig(
            corpus_path=corpus,
            checkpoint_path=checkpoint,
            max_steps=None,
            epochs=2,
            device="cpu",
            tokenizer_mode="bpe",
            tokenizer_vocab_size=260,
            tokenizer_output_path=tokenizer_path,
            model_config=model_config,
        ),
        hardware_profile=profile,
    )

    assert result.optimizer_steps_per_epoch > 0
    assert result.requested_steps == result.optimizer_steps_per_epoch * 2
    assert result.completed_steps == result.requested_steps
    assert result.epochs_completed == 2
    assert result.train_blocks_per_epoch > 0
    assert result.train_tokens_per_epoch > result.train_blocks_per_epoch
    assert result.inference_artifact_path.endswith("inference.pt")
    assert Path(result.inference_artifact_path).is_file()


def test_runner_trains_all_full_corpus_records_and_reports_in_sample_metrics(tmp_path):
    raw = tmp_path / "full-book-raw.jsonl"
    corpus = tmp_path / "full-book-prepared.jsonl"
    rows = [
        {
            "id": f"book-chunk-{index}",
            "text": (
                f"Complete book passage number {index}. "
                "AYFAM must process every approved paragraph in each full training epoch."
            ),
            "source": "full-book.pdf",
            "license": "owner permission",
            "split": "train",
            "group_id": "one-complete-book",
            "document_id": "one-complete-book",
            "title": "One complete book",
            "filename": "full-book.pdf",
            "file_type": "pdf",
            "page": index + 1,
            "chapter": "Training",
            "chunk_index": index,
            "language": "en",
        }
        for index in range(8)
    ]
    raw.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    prepare_corpus(raw, corpus, require_held_out=False)

    result = run_training(
        TrainingRunConfig(
            corpus_path=corpus,
            checkpoint_path=tmp_path / "full-book-run" / "latest.pt",
            max_steps=None,
            epochs=1,
            device="cpu",
            tokenizer_mode="bpe",
            tokenizer_vocab_size=260,
            model_config=ModelConfig(
                vocab_size=260,
                block_size=32,
                n_layer=1,
                n_head=2,
                n_embd=16,
                ffn_dim=32,
                dropout=0.0,
            ),
        ),
        hardware_profile=HardwareProfile(8_000, 3_000, 2, "x86_64", "test"),
    )

    assert result.train_records == 8
    assert result.evaluation_split == "train (in-sample)"
    assert result.evaluation_before is not None
    assert result.evaluation_after is not None
    assert result.validation_before is None
    assert result.test_before is None
    assert result.epochs_completed == 1
    assert result.completed_steps == result.optimizer_steps_per_epoch


def test_runner_does_not_activate_random_weights_when_stopped_before_first_update(tmp_path):
    corpus = _prepared_corpus(tmp_path)
    checkpoint = tmp_path / "stopped-run" / "latest.pt"
    artifact = tmp_path / "stopped-run" / "inference.pt"
    manifest = tmp_path / "active-model.json"
    model_config = ModelConfig(
        vocab_size=260,
        block_size=8,
        n_layer=1,
        n_head=2,
        n_embd=16,
        ffn_dim=32,
        dropout=0.0,
    )

    with pytest.raises(RuntimeError, match="before the first optimizer update"):
        run_training(
            TrainingRunConfig(
                corpus_path=corpus,
                checkpoint_path=checkpoint,
                max_steps=None,
                epochs=1,
                device="cpu",
                tokenizer_mode="bpe",
                tokenizer_vocab_size=260,
                inference_artifact_path=artifact,
                active_model_manifest_path=manifest,
                model_config=model_config,
            ),
            should_stop=lambda: True,
            hardware_profile=HardwareProfile(8_000, 3_000, 2, "x86_64", "test"),
        )

    assert not artifact.exists()
    assert not manifest.exists()


def test_training_config_defaults_to_automatic_steps_and_complete_epochs():
    from model_factory.cli import _parser

    args = _parser().parse_args(["train", "--corpus", "prepared.jsonl"])
    assert args.steps is None
    assert args.epochs == 3


def test_runner_resumes_from_a_matching_checkpoint_and_tokenizer(tmp_path):
    corpus = _prepared_corpus(tmp_path)
    run_dir = tmp_path / "resume-run"
    checkpoint = run_dir / "latest.pt"
    tokenizer_path = run_dir / "tokenizer.json"
    model_config = ModelConfig(
        vocab_size=260,
        block_size=32,
        n_layer=1,
        n_head=2,
        n_embd=16,
        ffn_dim=32,
        dropout=0.0,
    )
    profile = HardwareProfile(8_000, 3_000, 2, "x86_64", "test")
    first = run_training(
        TrainingRunConfig(
            corpus_path=corpus,
            checkpoint_path=checkpoint,
            max_steps=1,
            epochs=1,
            device="cpu",
            tokenizer_mode="bpe",
            tokenizer_vocab_size=260,
            tokenizer_output_path=tokenizer_path,
            model_config=model_config,
        ),
        hardware_profile=profile,
    )
    second = run_training(
        TrainingRunConfig(
            corpus_path=corpus,
            checkpoint_path=run_dir / "continued.pt",
            max_steps=None,
            epochs=1,
            device="cpu",
            tokenizer_mode="bpe",
            tokenizer_config_path=tokenizer_path,
            tokenizer_output_path=tokenizer_path,
            resume_checkpoint=checkpoint,
            previous_epochs_completed=4,
            model_config=model_config,
        ),
        hardware_profile=profile,
    )
    assert second.completed_steps > first.completed_steps
    assert second.workload["starting_step"] == first.completed_steps
    assert second.epochs_completed == 1
    assert second.epochs_completed_total == 5
