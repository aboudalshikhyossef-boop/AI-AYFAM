"""Shared CPU-first runner with full-corpus epoch planning and local activation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable

from model_factory.active_model import write_active_model_manifest
from model_factory.config import ModelConfig, TrainingConfig
from model_factory.corpus_tools import validate_prepared_corpus
from model_factory.data import iter_batches, iter_records
from model_factory.hardware import HardwareProfile, TrainingPlan, build_training_plan
from model_factory.inference import export_inference_artifact
from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer, load_tokenizer
from model_factory.training import StepResult, Trainer
from model_factory.workload import (
    TrainingWorkloadPlan,
    count_training_workload,
    measure_train_data_bytes,
    recommend_tokenizer_vocab_size,
)


@dataclass(frozen=True)
class TrainingRunConfig:
    corpus_path: Path
    checkpoint_path: Path
    # None means: calculate enough optimizer steps to cover every train block
    # for the requested number of complete epochs.
    max_steps: int | None = None
    epochs: int = 3
    device: str = "auto"
    seed: int = 42
    tokenizer_mode: str = "bpe"
    tokenizer_vocab_size: int | None = None
    tokenizer_min_frequency: int = 2
    tokenizer_config_path: Path | None = None
    tokenizer_output_path: Path | None = None
    resume_checkpoint: Path | None = None
    inference_artifact_path: Path | None = None
    active_model_manifest_path: Path | None = None
    previous_epochs_completed: int = 0
    model_config: ModelConfig | None = None

    def __post_init__(self) -> None:
        if self.max_steps is not None and (
            isinstance(self.max_steps, bool)
            or not isinstance(self.max_steps, int)
            or self.max_steps <= 0
        ):
            raise ValueError("max_steps must be a positive integer or None for automatic planning")
        if isinstance(self.epochs, bool) or not isinstance(self.epochs, int) or not 1 <= self.epochs <= 100:
            raise ValueError("epochs must be an integer between 1 and 100")
        if (
            isinstance(self.previous_epochs_completed, bool)
            or not isinstance(self.previous_epochs_completed, int)
            or self.previous_epochs_completed < 0
        ):
            raise ValueError("previous_epochs_completed must be a non-negative integer")
        if self.device not in {"auto", "cpu", "cuda"}:
            raise ValueError("device must be auto, cpu or cuda")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")
        if self.tokenizer_mode not in {"byte", "bpe"}:
            raise ValueError("tokenizer_mode must be byte or bpe")
        if self.tokenizer_vocab_size is not None and (
            isinstance(self.tokenizer_vocab_size, bool)
            or not isinstance(self.tokenizer_vocab_size, int)
            or self.tokenizer_vocab_size < ByteBPETokenizer.BASE_VOCAB_SIZE
        ):
            raise ValueError("tokenizer_vocab_size must be at least 260 or None for automatic selection")
        if (
            isinstance(self.tokenizer_min_frequency, bool)
            or not isinstance(self.tokenizer_min_frequency, int)
            or self.tokenizer_min_frequency < 1
        ):
            raise ValueError("tokenizer_min_frequency must be a positive integer")


@dataclass(frozen=True)
class TrainingRunResult:
    checkpoint_path: str
    tokenizer_path: str | None
    inference_artifact_path: str
    active_model_manifest_path: str
    corpus_fingerprint: str
    corpus_records: int
    train_records: int
    train_utf8_bytes: int
    train_tokens_per_epoch: int
    train_blocks_per_epoch: int
    optimizer_steps_per_epoch: int
    epochs_requested: int
    epochs_completed: int
    epochs_completed_total: int
    model_parameters: int
    tokenizer_vocab_size: int
    tokenizer_vocab_target: int
    completed_steps: int
    requested_steps: int
    stopped_early: bool
    device: str
    evaluation_split: str
    evaluation_before: dict[str, float] | None
    evaluation_after: dict[str, float] | None
    validation_before: dict[str, float] | None
    validation: dict[str, float] | None
    test_before: dict[str, float] | None
    test: dict[str, float] | None
    workload: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def run_training(
    config: TrainingRunConfig,
    *,
    on_step: Callable[[StepResult], bool | None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[[str], None] | None = None,
    on_plan: Callable[[dict[str, object]], None] | None = None,
    hardware_profile: HardwareProfile | None = None,
    training_plan: TrainingPlan | None = None,
) -> TrainingRunResult:
    """Train every train-split block for complete epochs, evaluate, and activate locally."""
    corpus_path = Path(config.corpus_path).expanduser()
    checkpoint_path = Path(config.checkpoint_path).expanduser()
    if corpus_path.is_symlink() or not corpus_path.is_file():
        raise OSError("prepared corpus must be an existing regular file, not a symlink")
    if checkpoint_path.is_symlink():
        raise OSError("checkpoint destination must not be a symlink")
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def phase(name: str) -> None:
        if on_phase is not None:
            on_phase(name)

    phase("validating_corpus")
    report = validate_prepared_corpus(corpus_path, require_held_out=False)
    has_validation = report.records_by_split.get("validation", 0) > 0
    has_test = report.records_by_split.get("test", 0) > 0
    if has_validation != has_test:
        raise ValueError(
            "prepared corpus must contain both Validation and Test splits, "
            "or use full-corpus Train-only mode"
        )
    has_independent_held_out = has_validation and has_test
    evaluation_split = (
        "validation/test (held-out)"
        if has_independent_held_out
        else "train (in-sample)"
    )

    profile = hardware_profile or HardwareProfile.detect()
    plan = training_plan or build_training_plan(profile)
    base_model_config = config.model_config or ModelConfig()

    phase("preparing_tokenizer")
    tokenizer_path = (
        Path(config.tokenizer_output_path).expanduser()
        if config.tokenizer_output_path is not None
        else checkpoint_path.parent / "tokenizer.json"
    )
    if tokenizer_path.is_symlink():
        raise OSError("tokenizer destination must not be a symlink")

    tokenizer_config_used: str | None = None
    if config.tokenizer_config_path is not None:
        tokenizer = load_tokenizer(config.tokenizer_config_path)
        tokenizer_config_used = str(Path(config.tokenizer_config_path).expanduser())
        tokenizer_target = tokenizer.vocab_size
        vocab_reason = "reusing the tokenizer bound to the previous checkpoint"
    elif config.tokenizer_mode == "bpe":
        if config.tokenizer_vocab_size is None:
            _train_records, train_bytes = measure_train_data_bytes(corpus_path)
            tokenizer_target, vocab_reason = recommend_tokenizer_vocab_size(train_bytes, profile)
        else:
            tokenizer_target = config.tokenizer_vocab_size
            vocab_reason = "explicit vocabulary target supplied by the user"
        tokenizer = ByteBPETokenizer.train_from_iterator(
            (record.text for record in iter_records(corpus_path, split="train")),
            vocab_size=tokenizer_target,
            min_frequency=config.tokenizer_min_frequency,
        )
        tokenizer.save(tokenizer_path)
        tokenizer_config_used = str(tokenizer_path)
    else:
        tokenizer = ByteTokenizer()
        tokenizer_target = tokenizer.vocab_size
        vocab_reason = "fixed UTF-8 byte vocabulary"

    model_config = replace(base_model_config, vocab_size=tokenizer.vocab_size)
    workload = count_training_workload(
        corpus_path,
        tokenizer,
        profile=profile,
        runtime_plan=plan,
        block_size=model_config.block_size,
        epochs=config.epochs,
        tokenizer_vocab_reason=vocab_reason,
    )
    planned_additional_steps = (
        config.max_steps if config.max_steps is not None else workload.additional_steps
    )
    if planned_additional_steps <= 0:
        raise ValueError("the calculated training step budget must be positive")

    try:
        import torch
        from model_factory.architecture import AYFAMTransformer
        from model_factory.checkpoint import load_checkpoint, save_checkpoint
    except (ImportError, RuntimeError) as exc:
        raise RuntimeError(
            "PyTorch is optional. Install requirements-training.txt before starting local training."
        ) from exc

    # A placeholder total lets the checkpoint loader validate the same optimizer
    # settings. The target is expanded after its saved global step is restored.
    initial_target = planned_additional_steps
    training_config = TrainingConfig(
        max_steps=initial_target,
        batch_size=plan.micro_batch_size,
        gradient_accumulation_steps=plan.gradient_accumulation_steps,
        checkpoint_interval_steps=min(plan.checkpoint_interval_steps, initial_target),
        num_threads=plan.num_threads,
        seed=config.seed,
    )
    torch.manual_seed(config.seed)
    model = AYFAMTransformer(model_config)
    trainer = Trainer(
        model,
        training_config,
        device=config.device,
        data_fingerprint=report.fingerprint,
        hardware_profile=profile,
        plan=plan,
    )

    if config.resume_checkpoint is not None:
        phase("resuming_checkpoint")
        load_checkpoint(
            config.resume_checkpoint,
            trainer,
            tokenizer,
            expected_data_fingerprint=report.fingerprint,
        )

    starting_step = trainer.global_step
    target_steps = (
        config.max_steps
        if config.max_steps is not None
        else starting_step + planned_additional_steps
    )
    if target_steps <= starting_step:
        raise ValueError("the requested target is not beyond the checkpoint's current step")
    trainer.config = replace(
        trainer.config,
        max_steps=target_steps,
        checkpoint_interval_steps=min(plan.checkpoint_interval_steps, target_steps),
    )

    workload_payload = workload.to_dict()
    workload_payload.update({
        "evaluation_split": evaluation_split,
        "starting_step": starting_step,
        "target_global_step": target_steps,
        "additional_steps": target_steps - starting_step,
        "tokenizer_vocab_target": tokenizer_target,
        "tokenizer_vocab_actual": tokenizer.vocab_size,
        "hardware_profile": profile.to_dict(),
        "runtime_plan": plan.to_dict(),
    })
    if on_plan is not None:
        on_plan(workload_payload)

    def batch_factory():
        # Every call is one complete streamed pass over the entire train split.
        return iter_batches(
            corpus_path,
            tokenizer,
            split="train",
            block_size=model_config.block_size,
            batch_size=plan.micro_batch_size,
            shuffle=True,
            seed=config.seed + trainer.global_step,
        )

    def evaluate_split(split: str) -> dict[str, float]:
        factory = lambda: iter_batches(
            corpus_path,
            tokenizer,
            split=split,
            block_size=model_config.block_size,
            batch_size=plan.micro_batch_size,
            shuffle=False,
        )
        return Trainer.evaluate(model, factory, device=trainer.device)

    phase("evaluating_before")
    evaluation_before: dict[str, float] | None = None
    evaluation_after: dict[str, float] | None = None
    validation_before: dict[str, float] | None = None
    test_before: dict[str, float] | None = None
    if has_independent_held_out:
        validation_before = evaluate_split("validation")
        test_before = evaluate_split("test")
    else:
        # Full-book mode intentionally spends every approved record on training.
        # Its before/after score is in-sample, never described as independent validation.
        evaluation_before = evaluate_split("train")

    phase("training")

    def report_step(result: StepResult) -> bool:
        keep_going = True
        if on_step is not None and on_step(result) is False:
            keep_going = False
        return keep_going and not (should_stop is not None and should_stop())

    if should_stop is not None and should_stop():
        save_checkpoint(checkpoint_path, trainer, tokenizer)
    else:
        trainer.fit(
            batch_factory,
            max_steps=target_steps,
            checkpoint_path=str(checkpoint_path),
            checkpoint_interval_steps=trainer.config.checkpoint_interval_steps,
            tokenizer=tokenizer,
            on_step=report_step,
        )

    if trainer.global_step == 0:
        raise RuntimeError(
            "training stopped before the first optimizer update; "
            "the random initialization was not activated as a trained chat model"
        )

    validation_after: dict[str, float] | None = None
    test_after: dict[str, float] | None = None
    if trainer.global_step > starting_step:
        phase("evaluating_after")
        if has_independent_held_out:
            validation_after = evaluate_split("validation")
            test_after = evaluate_split("test")
        else:
            evaluation_after = evaluate_split("train")
    elif trainer.global_step > 0:
        # Preserve the last learned state even when the stop button was pressed
        # before the next optimizer update; the current model is still valid.
        if has_independent_held_out:
            validation_after = validation_before
            test_after = test_before
        else:
            evaluation_after = evaluation_before

    artifact_path = (
        Path(config.inference_artifact_path).expanduser()
        if config.inference_artifact_path is not None
        else checkpoint_path.parent / "inference.pt"
    )
    manifest_path = (
        Path(config.active_model_manifest_path).expanduser()
        if config.active_model_manifest_path is not None
        else checkpoint_path.parent / "active-model.json"
    )
    phase("exporting_model")
    export_inference_artifact(checkpoint_path, artifact_path)
    epochs_completed = min(
        config.epochs,
        max(0, (trainer.global_step - starting_step) // workload.optimizer_steps_per_epoch),
    )
    write_active_model_manifest(
        manifest_path,
        artifact_path=artifact_path,
        checkpoint_path=checkpoint_path,
        corpus_path=corpus_path,
        tokenizer_path=tokenizer_config_used,
        data_fingerprint=report.fingerprint,
        global_step=trainer.global_step,
        model_parameters=model.parameter_count(),
        tokenizer_vocab_size=tokenizer.vocab_size,
        epochs_completed=config.previous_epochs_completed + epochs_completed,
        evaluation_split=evaluation_split,
        evaluation_before=evaluation_before,
        evaluation_after=evaluation_after,
        validation_before=validation_before,
        validation_after=validation_after,
        test_before=test_before,
        test_after=test_after,
    )

    phase("completed")
    return TrainingRunResult(
        checkpoint_path=str(checkpoint_path),
        tokenizer_path=tokenizer_config_used,
        inference_artifact_path=str(artifact_path),
        active_model_manifest_path=str(manifest_path),
        corpus_fingerprint=report.fingerprint,
        corpus_records=report.total_records,
        train_records=workload.train_records,
        train_utf8_bytes=workload.train_utf8_bytes,
        train_tokens_per_epoch=workload.train_tokens,
        train_blocks_per_epoch=workload.train_blocks_per_epoch,
        optimizer_steps_per_epoch=workload.optimizer_steps_per_epoch,
        epochs_requested=config.epochs,
        epochs_completed=epochs_completed,
        epochs_completed_total=config.previous_epochs_completed + epochs_completed,
        evaluation_split=evaluation_split,
        evaluation_before=evaluation_before,
        evaluation_after=evaluation_after,
        model_parameters=model.parameter_count(),
        tokenizer_vocab_size=tokenizer.vocab_size,
        tokenizer_vocab_target=tokenizer_target,
        completed_steps=trainer.global_step,
        requested_steps=target_steps,
        stopped_early=trainer.global_step < target_steps,
        device=str(trainer.device),
        validation_before=validation_before,
        validation=validation_after,
        test_before=test_before,
        test=test_after,
        workload=workload_payload,
    )
