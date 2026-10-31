"""Shared, CPU-first training runner used by the CLI and desktop workspace."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from model_factory.config import ModelConfig, TrainingConfig
from model_factory.corpus_tools import validate_prepared_corpus
from model_factory.data import iter_batches, iter_records
from model_factory.hardware import HardwareProfile, TrainingPlan, build_training_plan
from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer, load_tokenizer
from model_factory.training import StepResult, Trainer


@dataclass(frozen=True)
class TrainingRunConfig:
    corpus_path: Path
    checkpoint_path: Path
    max_steps: int = 1_000
    device: str = "auto"
    seed: int = 42
    tokenizer_mode: str = "byte"
    tokenizer_vocab_size: int = 512
    tokenizer_min_frequency: int = 2
    tokenizer_config_path: Path | None = None
    tokenizer_output_path: Path | None = None
    resume_checkpoint: Path | None = None
    model_config: ModelConfig | None = None

    def __post_init__(self) -> None:
        if isinstance(self.max_steps, bool) or not isinstance(self.max_steps, int) or self.max_steps <= 0:
            raise ValueError("max_steps must be a positive integer")
        if self.device not in {"auto", "cpu", "cuda"}:
            raise ValueError("device must be auto, cpu or cuda")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")
        if self.tokenizer_mode not in {"byte", "bpe"}:
            raise ValueError("tokenizer_mode must be byte or bpe")
        if (
            isinstance(self.tokenizer_vocab_size, bool)
            or not isinstance(self.tokenizer_vocab_size, int)
            or self.tokenizer_vocab_size < ByteBPETokenizer.BASE_VOCAB_SIZE
        ):
            raise ValueError("tokenizer_vocab_size must be at least 260")
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
    corpus_fingerprint: str
    corpus_records: int
    model_parameters: int
    tokenizer_vocab_size: int
    completed_steps: int
    requested_steps: int
    stopped_early: bool
    device: str
    validation: dict[str, float] | None

    def to_dict(self) -> dict[str, object]:
        return {
            "checkpoint_path": self.checkpoint_path,
            "tokenizer_path": self.tokenizer_path,
            "corpus_fingerprint": self.corpus_fingerprint,
            "corpus_records": self.corpus_records,
            "model_parameters": self.model_parameters,
            "tokenizer_vocab_size": self.tokenizer_vocab_size,
            "completed_steps": self.completed_steps,
            "requested_steps": self.requested_steps,
            "stopped_early": self.stopped_early,
            "device": self.device,
            "validation": self.validation,
        }


def run_training(
    config: TrainingRunConfig,
    *,
    on_step: Callable[[StepResult], bool | None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[[str], None] | None = None,
    hardware_profile: HardwareProfile | None = None,
    training_plan: TrainingPlan | None = None,
) -> TrainingRunResult:
    """Validate data, build/load the tokenizer, train, checkpoint and evaluate locally."""
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
    report = validate_prepared_corpus(corpus_path, require_held_out=True)
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
    elif config.tokenizer_mode == "bpe":
        if config.resume_checkpoint is not None and tokenizer_path.is_file():
            tokenizer = load_tokenizer(tokenizer_path)
            tokenizer_config_used = str(tokenizer_path)
        else:
            tokenizer = ByteBPETokenizer.train_from_iterator(
                (record.text for record in iter_records(corpus_path, split="train")),
                vocab_size=config.tokenizer_vocab_size,
                min_frequency=config.tokenizer_min_frequency,
            )
            tokenizer.save(tokenizer_path)
            tokenizer_config_used = str(tokenizer_path)
    else:
        tokenizer = ByteTokenizer()

    try:
        import torch
        from model_factory.architecture import AYFAMTransformer
        from model_factory.checkpoint import load_checkpoint, save_checkpoint
    except (ImportError, RuntimeError) as exc:
        raise RuntimeError(
            "PyTorch is optional. Install requirements-training.txt before starting local training."
        ) from exc

    profile = hardware_profile or HardwareProfile.detect()
    plan = training_plan or build_training_plan(profile)
    base_model_config = config.model_config or ModelConfig()
    model_config = replace(base_model_config, vocab_size=tokenizer.vocab_size)
    training_config = TrainingConfig(
        max_steps=config.max_steps,
        batch_size=plan.micro_batch_size,
        gradient_accumulation_steps=plan.gradient_accumulation_steps,
        checkpoint_interval_steps=min(plan.checkpoint_interval_steps, config.max_steps),
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

    phase("training")
    starting_step = trainer.global_step

    def batch_factory():
        return iter_batches(
            corpus_path,
            tokenizer,
            split="train",
            block_size=model_config.block_size,
            batch_size=plan.micro_batch_size,
            shuffle=True,
            seed=config.seed + trainer.global_step,
        )

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
            max_steps=config.max_steps,
            checkpoint_path=str(checkpoint_path),
            checkpoint_interval_steps=training_config.checkpoint_interval_steps,
            tokenizer=tokenizer,
            on_step=report_step,
        )

    validation: dict[str, float] | None = None
    if trainer.global_step > starting_step:
        phase("evaluating")
        validation_factory = lambda: iter_batches(
            corpus_path,
            tokenizer,
            split="validation",
            block_size=model_config.block_size,
            batch_size=plan.micro_batch_size,
        )
        validation = Trainer.evaluate(model, validation_factory, device=trainer.device)

    phase("completed")
    return TrainingRunResult(
        checkpoint_path=str(checkpoint_path),
        tokenizer_path=tokenizer_config_used,
        corpus_fingerprint=report.fingerprint,
        corpus_records=report.total_records,
        model_parameters=model.parameter_count(),
        tokenizer_vocab_size=tokenizer.vocab_size,
        completed_steps=trainer.global_step,
        requested_steps=config.max_steps,
        stopped_early=trainer.global_step < config.max_steps,
        device=str(trainer.device),
        validation=validation,
    )
