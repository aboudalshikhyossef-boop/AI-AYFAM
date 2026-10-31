"""Optional CPU smoke tests for the actual neural model and checkpoint flow."""

import json

import pytest

torch = pytest.importorskip("torch")

from model_factory.architecture import AYFAMTransformer
from model_factory.checkpoint import load_checkpoint, save_checkpoint
from model_factory.data import iter_batches
from model_factory.config import ModelConfig, TrainingConfig
from model_factory.hardware import HardwareProfile, TrainingPlan
from model_factory.tokenizer import ByteTokenizer
from model_factory.training import Trainer


def _small_model_config():
    return ModelConfig(
        vocab_size=260,
        block_size=16,
        n_layer=2,
        n_head=4,
        n_embd=32,
        ffn_dim=64,
        dropout=0.0,
    )


def _trainer(model, fingerprint="a" * 64):
    profile = HardwareProfile(8_000, 4_000, 4, "x86_64", "test")
    plan = TrainingPlan(1, 1, 1, 10, 800, ("test",))
    return Trainer(
        model,
        TrainingConfig(
            max_steps=3,
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


def test_default_architecture_has_exactly_three_million_parameters():
    model = AYFAMTransformer()
    assert model.parameter_count() == 3_042_432


def test_transformer_forward_has_finite_loss_and_expected_shape():
    model = AYFAMTransformer(_small_model_config())
    inputs = torch.randint(0, 256, (2, 8), dtype=torch.long)
    targets = torch.randint(0, 256, (2, 8), dtype=torch.long)
    output = model(inputs, targets)
    assert output["logits"].shape == (2, 8, 260)
    assert output["loss"].ndim == 0
    assert torch.isfinite(output["loss"])
    assert model.parameter_count() == sum(p.numel() for p in model.parameters())


def test_attention_is_causal():
    torch.manual_seed(7)
    model = AYFAMTransformer(_small_model_config()).eval()
    first = torch.tensor([[1, 2, 3, 4, 5]], dtype=torch.long)
    changed_future = torch.tensor([[1, 2, 3, 99, 98]], dtype=torch.long)
    with torch.no_grad():
        left = model(first)["logits"]
        right = model(changed_future)["logits"]
    assert torch.allclose(left[:, :3], right[:, :3], atol=1e-6, rtol=1e-6)


def test_train_step_updates_weights_and_checkpoint_resumes(tmp_path):
    torch.manual_seed(123)
    model = AYFAMTransformer(_small_model_config())
    trainer = _trainer(model)
    inputs = torch.randint(0, 256, (1, 8), dtype=torch.long)
    targets = torch.randint(0, 256, (1, 8), dtype=torch.long)
    before = model.token_embedding.weight.detach().clone()
    result = trainer.train_batch(inputs, targets)
    assert result.step == 1
    assert result.loss > 0
    assert not torch.equal(before, model.token_embedding.weight)

    tokenizer = ByteTokenizer()
    checkpoint = tmp_path / "latest.pt"
    save_checkpoint(checkpoint, trainer, tokenizer)
    restored = AYFAMTransformer(_small_model_config())
    restored_trainer = _trainer(restored)
    metadata = load_checkpoint(
        checkpoint,
        restored_trainer,
        tokenizer,
        expected_data_fingerprint="a" * 64,
    )
    assert metadata["global_step"] == 1
    assert restored_trainer.global_step == 1
    assert all(
        torch.equal(left, right)
        for left, right in zip(model.state_dict().values(), restored.state_dict().values())
    )


def test_checkpoint_refuses_a_different_corpus(tmp_path):
    model = AYFAMTransformer(_small_model_config())
    trainer = _trainer(model)
    checkpoint = tmp_path / "latest.pt"
    save_checkpoint(checkpoint, trainer, ByteTokenizer())
    other = _trainer(AYFAMTransformer(_small_model_config()), fingerprint="b" * 64)
    with pytest.raises(ValueError, match="fingerprint"):
        load_checkpoint(checkpoint, other, ByteTokenizer())


def test_fit_restarts_streaming_batches_and_saves_final_checkpoint(tmp_path):
    model = AYFAMTransformer(_small_model_config())
    trainer = _trainer(model)
    tokenizer = ByteTokenizer()
    inputs = torch.randint(0, 256, (1, 8), dtype=torch.long)
    targets = torch.randint(0, 256, (1, 8), dtype=torch.long)
    calls = {"count": 0}

    def batch_factory():
        calls["count"] += 1
        return iter([(inputs, targets)])

    checkpoint = tmp_path / "fit.pt"
    history = trainer.fit(
        batch_factory,
        max_steps=2,
        checkpoint_path=str(checkpoint),
        tokenizer=tokenizer,
        checkpoint_interval_steps=1,
    )
    assert len(history) == 2
    assert trainer.global_step == 2
    assert calls["count"] == 2
    assert checkpoint.is_file()


def test_checkpoint_refuses_optimizer_hyperparameter_drift(tmp_path):
    model = AYFAMTransformer(_small_model_config())
    trainer = _trainer(model)
    checkpoint = tmp_path / "hyperparameters.pt"
    save_checkpoint(checkpoint, trainer, ByteTokenizer())
    changed_config = TrainingConfig(
        max_steps=3,
        batch_size=1,
        gradient_accumulation_steps=1,
        learning_rate=1e-4,
        warmup_steps=0,
        checkpoint_interval_steps=1,
        num_threads=1,
    )
    changed = Trainer(
        AYFAMTransformer(_small_model_config()),
        changed_config,
        device="cpu",
        data_fingerprint="a" * 64,
        hardware_profile=trainer.hardware_profile,
        plan=trainer.plan,
    )
    with pytest.raises(ValueError, match="learning_rate"):
        load_checkpoint(checkpoint, changed, ByteTokenizer())


def test_streaming_batch_shuffle_is_reproducible_and_reorders_records(tmp_path):
    corpus = tmp_path / "shuffle.jsonl"
    rows = []
    for index in range(10):
        text = chr(65 + index) * 4
        rows.append({
            "id": str(index),
            "text": text,
            "source": "test",
            "license": "CC0-1.0",
            "split": "train",
        })
    corpus.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )

    def order(shuffle, seed=17):
        batches = iter_batches(
            corpus,
            ByteTokenizer(),
            split="train",
            block_size=5,
            batch_size=1,
            shuffle=shuffle,
            seed=seed,
            shuffle_buffer_size=10,
        )
        return [int(inputs[0, 1]) for inputs, _ in batches]

    sequential = order(False)
    shuffled = order(True)
    assert shuffled == order(True)
    assert shuffled != sequential
    assert sorted(shuffled) == sorted(sequential)


def test_checkpoint_contains_only_safe_rng_metadata(tmp_path):
    trainer = _trainer(AYFAMTransformer(_small_model_config()))
    checkpoint = tmp_path / "rng.pt"
    save_checkpoint(checkpoint, trainer, ByteTokenizer())
    payload = torch.load(checkpoint, map_location="cpu", weights_only=True)
    assert isinstance(payload["torch_rng_state"], torch.Tensor)
    assert isinstance(payload["torch_cuda_rng_states"], list)
