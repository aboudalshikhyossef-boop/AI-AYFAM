"""CPU tests for model-only artifacts, local generation and held-out evaluation."""

import json

import pytest

torch = pytest.importorskip("torch")

from model_factory.architecture import AYFAMTransformer
from model_factory.benchmark import benchmark_model
from model_factory.checkpoint import save_checkpoint
from model_factory.config import ModelConfig, TrainingConfig
from model_factory.corpus_tools import prepare_corpus
from model_factory.evaluation import evaluate_model
from model_factory.hardware import HardwareProfile, TrainingPlan
from model_factory.inference import (
    export_inference_artifact,
    generate_text,
    load_inference_model,
)
from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer
from model_factory.training import Trainer


def _small_config(vocab_size=260):
    return ModelConfig(
        vocab_size=vocab_size,
        block_size=16,
        n_layer=2,
        n_head=4,
        n_embd=32,
        ffn_dim=64,
        dropout=0.0,
    )


def _trainer(config, fingerprint):
    profile = HardwareProfile(8_000, 4_000, 4, "x86_64", "test")
    plan = TrainingPlan(1, 1, 1, 10, 800, ("test",))
    model = AYFAMTransformer(config)
    trainer = Trainer(
        model,
        TrainingConfig(
            max_steps=2,
            batch_size=1,
            gradient_accumulation_steps=1,
            warmup_steps=0,
            checkpoint_interval_steps=1,
            num_threads=1,
        ),
        device="cpu",
        data_fingerprint=fingerprint,
        hardware_profile=profile,
        plan=plan,
    )
    return trainer


def _prepared_corpus(path):
    raw = path.with_name("raw.jsonl")
    records = [
        {"text": "نص عربي للتدريب", "source": "doc-train", "license": "owner-permission", "split": "train"},
        {"text": "English validation passage", "source": "doc-validation", "license": "CC0-1.0", "split": "validation"},
        {"text": "مقطع مستقل للاختبار", "source": "doc-test", "license": "CC0-1.0", "split": "test"},
    ]
    raw.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records),
        encoding="utf-8",
    )
    return prepare_corpus(raw, path, require_held_out=True)


def _export_small_artifact(tmp_path, tokenizer=None):
    tokenizer = tokenizer or ByteTokenizer()
    config = _small_config(tokenizer.vocab_size)
    fingerprint = "a" * 64
    trainer = _trainer(config, fingerprint)
    checkpoint = tmp_path / "training.pt"
    artifact = tmp_path / "inference.pt"
    save_checkpoint(checkpoint, trainer, tokenizer)
    export_inference_artifact(checkpoint, artifact)
    return trainer, checkpoint, artifact, load_inference_model(artifact, device="cpu")


def test_export_creates_model_only_artifact_without_optimizer_state(tmp_path):
    trainer, checkpoint, artifact, loaded = _export_small_artifact(tmp_path)
    training_payload = torch.load(checkpoint, map_location="cpu", weights_only=True)
    artifact_payload = torch.load(artifact, map_location="cpu", weights_only=True)

    assert "optimizer_state" in training_payload
    assert "optimizer_state" not in artifact_payload
    assert artifact_payload["artifact_schema_version"] == 1
    assert loaded.config.vocab_size == 260
    assert loaded.model.parameter_count() == trainer.model.parameter_count()
    assert loaded.model.parameter_count() == loaded.metadata["parameter_count"]


def test_bpe_model_artifact_round_trips_with_its_exact_tokenizer(tmp_path):
    tokenizer = ByteBPETokenizer.train_from_iterator(
        ["الأمن السيبراني AI AYFAM"] * 4,
        vocab_size=280,
        min_frequency=2,
    )
    _, _, _, loaded = _export_small_artifact(tmp_path, tokenizer)
    assert isinstance(loaded.tokenizer, ByteBPETokenizer)
    assert loaded.tokenizer.to_dict() == tokenizer.to_dict()
    assert loaded.config.vocab_size == tokenizer.vocab_size


def test_export_rejects_same_input_and_output_path(tmp_path):
    _, checkpoint, _, _ = _export_small_artifact(tmp_path)
    with pytest.raises(ValueError, match="different files"):
        export_inference_artifact(checkpoint, checkpoint)


def test_loader_rejects_invalid_artifact_schema(tmp_path):
    path = tmp_path / "invalid.pt"
    torch.save({"artifact_schema_version": 999}, path)
    with pytest.raises(ValueError, match="schema"):
        load_inference_model(path)


def test_generation_is_seeded_and_restores_model_mode(tmp_path):
    _, _, _, loaded = _export_small_artifact(tmp_path)
    loaded.model.train()
    first = generate_text(
        loaded, "AI AYFAM", max_new_tokens=5,
        temperature=0.8, top_k=12, top_p=0.9, seed=55,
    )
    second = generate_text(
        loaded, "AI AYFAM", max_new_tokens=5,
        temperature=0.8, top_k=12, top_p=0.9, seed=55,
    )
    assert first.generated_token_ids == second.generated_token_ids
    assert first.generated_token_count <= 5
    assert loaded.model.training is True


def test_generation_greedy_mode_and_zero_tokens(tmp_path):
    _, _, _, loaded = _export_small_artifact(tmp_path)
    result = generate_text(
        loaded, "مرحبا", max_new_tokens=0, temperature=0,
        top_k=None, top_p=None,
    )
    assert result.text == ""
    assert result.generated_token_count == 0
    greedy_a = generate_text(loaded, "hello", max_new_tokens=4, temperature=0, seed=1)
    greedy_b = generate_text(loaded, "hello", max_new_tokens=4, temperature=0, seed=999)
    assert greedy_a.generated_token_ids == greedy_b.generated_token_ids


@pytest.mark.parametrize("kwargs", [
    {"max_new_tokens": -1},
    {"max_new_tokens": 9000},
    {"temperature": -0.1},
    {"temperature": float("nan")},
    {"top_k": 0},
    {"top_p": 0},
    {"top_p": 1.1},
])
def test_generation_rejects_invalid_sampling_settings(tmp_path, kwargs):
    _, _, _, loaded = _export_small_artifact(tmp_path)
    with pytest.raises(ValueError):
        generate_text(loaded, "hello", **kwargs)


def test_evaluation_reports_token_weighted_loss_accuracy_and_fingerprint(tmp_path):
    corpus = tmp_path / "prepared.jsonl"
    report = _prepared_corpus(corpus)
    trainer, _, artifact, loaded = _export_small_artifact(tmp_path)
    trainer.data_fingerprint = report.fingerprint
    checkpoint = tmp_path / "with-corpus.pt"
    save_checkpoint(checkpoint, trainer, loaded.tokenizer)
    export_inference_artifact(checkpoint, artifact)
    loaded = load_inference_model(artifact, device="cpu")

    metrics = evaluate_model(loaded, str(corpus), split="test", batch_size=1)
    assert metrics["split"] == "test"
    assert metrics["tokens_evaluated"] > 0
    assert 0.0 <= metrics["next_token_accuracy"] <= 1.0
    assert metrics["loss"] > 0
    assert metrics["perplexity"] >= 1.0
    assert metrics["corpus_fingerprint"] == report.fingerprint


def test_evaluation_refuses_a_different_corpus_fingerprint(tmp_path):
    _, _, _, loaded = _export_small_artifact(tmp_path)
    corpus = tmp_path / "prepared.jsonl"
    _prepared_corpus(corpus)
    with pytest.raises(ValueError, match="fingerprint"):
        evaluate_model(loaded, str(corpus), split="validation")


def test_evaluation_rejects_training_split_and_empty_limits(tmp_path):
    _, _, _, loaded = _export_small_artifact(tmp_path)
    with pytest.raises(ValueError, match="validation or test"):
        evaluate_model(loaded, "unused", split="train")
    with pytest.raises(ValueError, match="max_batches"):
        evaluate_model(loaded, "unused", split="test", max_batches=0)


def test_benchmark_measures_forward_and_generation_without_changing_mode(tmp_path):
    _, _, _, loaded = _export_small_artifact(tmp_path)
    loaded.model.train()
    result = benchmark_model(
        loaded,
        batch_size=1,
        sequence_length=8,
        warmup_iterations=1,
        iterations=2,
        generation_tokens=3,
        threads=1,
    )
    assert result["forward_tokens"] == 16
    assert result["forward_tokens_per_second"] > 0
    assert result["generated_tokens"] == 3
    assert result["generation_tokens_per_second"] > 0
    assert result["threads"] == 1
    assert loaded.model.training is True


def test_benchmark_validates_shapes_and_iteration_counts(tmp_path):
    _, _, _, loaded = _export_small_artifact(tmp_path)
    with pytest.raises(ValueError, match="sequence_length"):
        benchmark_model(loaded, sequence_length=loaded.config.block_size + 1)
    with pytest.raises(ValueError, match="iterations"):
        benchmark_model(loaded, iterations=0)



def test_cli_exposes_export_generation_evaluation_and_benchmark_commands():
    from model_factory.cli import _parser

    parser = _parser()
    for command in ("export-model", "generate", "evaluate", "benchmark"):
        parsed = parser.parse_args(
            ["export-model", "--checkpoint", "x", "--output", "y"]
            if command == "export-model"
            else ["generate", "--model", "x", "--prompt", "hello"]
            if command == "generate"
            else ["evaluate", "--model", "x", "--corpus", "y"]
            if command == "evaluate"
            else ["benchmark", "--model", "x"]
        )
        assert parsed.command == command
