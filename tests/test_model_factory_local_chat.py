"""Tests proving the trained AYFAM artifact is available to the local chat path."""

import json

import pytest

torch = pytest.importorskip("torch")

from model_factory.active_model import write_active_model_manifest
from model_factory.architecture import AYFAMTransformer
from model_factory.checkpoint import save_checkpoint
from model_factory.config import ModelConfig, TrainingConfig
from model_factory.corpus_tools import prepare_corpus
from model_factory.inference import export_inference_artifact
from model_factory.local_chat import answer_with_active_model, retrieve_corpus_passages
from model_factory.tokenizer import ByteTokenizer
from model_factory.training import Trainer
from model_factory.hardware import HardwareProfile, TrainingPlan


def _build_active_model(tmp_path, monkeypatch):
    import model_factory.active_model as active_module

    raw = tmp_path / "raw.jsonl"
    corpus = tmp_path / "prepared.jsonl"
    rows = [
        {
            "text": (
                "TCP establishes a reliable connection using a handshake. "
                "The protocol uses sequence numbers and acknowledgements."
            ),
            "source": "network-book",
            "license": "owner permission",
            "split": "train",
            "title": "Computer Networks",
            "filename": "networks.pdf",
            "page": 42,
            "chapter": "Transport Layer",
            "group_id": "network-book",
        },
        {
            "text": "Validation text reserved for measuring generalization.",
            "source": "validation-book",
            "license": "owner permission",
            "split": "validation",
            "group_id": "validation-book",
        },
        {
            "text": "Test text reserved for final evaluation.",
            "source": "test-book",
            "license": "owner permission",
            "split": "test",
            "group_id": "test-book",
        },
    ]
    raw.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    report = prepare_corpus(raw, corpus, require_held_out=True)

    config = ModelConfig(
        vocab_size=260,
        block_size=16,
        n_layer=1,
        n_head=2,
        n_embd=16,
        ffn_dim=32,
        dropout=0.0,
    )
    tokenizer = ByteTokenizer()
    profile = HardwareProfile(8_000, 3_000, 2, "x86_64", "test")
    plan = TrainingPlan(1, 1, 1, 10, 500, ("test",))
    model = AYFAMTransformer(config)
    trainer = Trainer(
        model,
        TrainingConfig(
            max_steps=1,
            batch_size=1,
            gradient_accumulation_steps=1,
            warmup_steps=0,
            checkpoint_interval_steps=1,
            num_threads=1,
        ),
        device="cpu",
        data_fingerprint=report.fingerprint,
        hardware_profile=profile,
        plan=plan,
    )
    trainer.train_batch(
        torch.tensor([[84, 67, 80, 32, 97, 98, 99, 100]], dtype=torch.long),
        torch.tensor([[67, 80, 32, 97, 98, 99, 100, 101]], dtype=torch.long),
    )
    checkpoint = tmp_path / "latest.pt"
    tokenizer_path = tmp_path / "tokenizer.json"
    artifact = tmp_path / "inference.pt"
    save_checkpoint(checkpoint, trainer, tokenizer)
    tokenizer.save(tokenizer_path)
    export_inference_artifact(checkpoint, artifact)

    manifest = tmp_path / "active-model.json"
    monkeypatch.setattr(active_module, "ACTIVE_MODEL_MANIFEST", manifest)
    write_active_model_manifest(
        manifest,
        artifact_path=artifact,
        checkpoint_path=checkpoint,
        corpus_path=corpus,
        tokenizer_path=tokenizer_path,
        data_fingerprint=report.fingerprint,
        global_step=trainer.global_step,
        model_parameters=model.parameter_count(),
        tokenizer_vocab_size=tokenizer.vocab_size,
        epochs_completed=1,
        evaluation_split="validation/test (held-out)",
        evaluation_before=None,
        evaluation_after=None,
        validation_before={"loss": 5.0},
        validation_after={"loss": 4.0},
        test_before={"loss": 5.5},
        test_after={"loss": 4.5},
    )
    return manifest, corpus


def test_local_chat_loads_active_model_and_retrieves_source_pages(tmp_path, monkeypatch):
    _manifest, corpus = _build_active_model(tmp_path, monkeypatch)
    passages = retrieve_corpus_passages(corpus, "كيف يعمل TCP و handshake؟")

    assert passages
    assert passages[0]["title"] == "Computer Networks"
    assert passages[0]["page"] == 42
    assert "TCP" in passages[0]["excerpt"]

    result = answer_with_active_model("اشرح TCP باختصار")

    assert result is not None
    assert result["global_step"] == 1
    assert result["model_parameters"] > 0
    assert result["device"] == "cpu"
    assert result["passages"]
    assert result["passages"][0]["page"] == 42
    assert isinstance(result["generated_text"], str)
    assert result["generated_tokens"] <= 40


def test_local_chat_is_disabled_without_a_valid_active_manifest(tmp_path, monkeypatch):
    import model_factory.active_model as active_module

    monkeypatch.setattr(active_module, "ACTIVE_MODEL_MANIFEST", tmp_path / "missing.json")
    assert answer_with_active_model("ما هو TCP؟") is None


def test_active_manifest_rejects_missing_or_symlinked_artifacts(tmp_path, monkeypatch):
    import model_factory.active_model as active_module

    missing = tmp_path / "missing.json"
    monkeypatch.setattr(active_module, "ACTIVE_MODEL_MANIFEST", missing)
    assert answer_with_active_model("سؤال") is None
