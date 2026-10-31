"""Command-line entry points for model profiling, corpus validation and training."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from model_factory.config import ModelConfig, TrainingConfig
from model_factory.data import iter_batches, validate_corpus
from model_factory.hardware import HardwareProfile, build_training_plan
from model_factory.tokenizer import ByteTokenizer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ayfam-model", description="AI AYFAM from-scratch model tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("profile", help="show a hardware-aware CPU training plan")
    validate = commands.add_parser("validate-corpus", help="validate provenance-aware JSONL training data")
    validate.add_argument("corpus", type=Path)
    train = commands.add_parser("train", help="train the randomly initialized AI AYFAM Transformer")
    train.add_argument("--corpus", type=Path, required=True)
    train.add_argument("--output", type=Path, default=Path("runs/ayfam-3m/latest.pt"))
    train.add_argument("--steps", type=int, default=1_000)
    train.add_argument("--resume", type=Path)
    train.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "profile":
        profile = HardwareProfile.detect()
        plan = build_training_plan(profile)
        print(json.dumps({"hardware": profile.to_dict(), "training_plan": plan.to_dict()}, ensure_ascii=False, indent=2))
        return 0
    if args.command == "validate-corpus":
        report = validate_corpus(args.corpus)
        print(json.dumps({
            "path": report.path,
            "fingerprint": report.fingerprint,
            "records_by_split": report.records_by_split,
            "total_records": report.total_records,
        }, ensure_ascii=False, indent=2))
        return 0

    if args.command == "train":
        try:
            import torch
            from model_factory.architecture import AYFAMTransformer
            from model_factory.checkpoint import load_checkpoint
            from model_factory.training import Trainer
        except (ImportError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.steps <= 0:
            print("--steps must be positive", file=sys.stderr)
            return 2
        try:
            report = validate_corpus(args.corpus)
            profile = HardwareProfile.detect()
            plan = build_training_plan(profile)
            model_config = ModelConfig()
            training_config = TrainingConfig(
                max_steps=args.steps,
                batch_size=plan.micro_batch_size,
                gradient_accumulation_steps=plan.gradient_accumulation_steps,
                checkpoint_interval_steps=plan.checkpoint_interval_steps,
                num_threads=plan.num_threads,
            )
            torch.manual_seed(training_config.seed)
            tokenizer = ByteTokenizer()
            model = AYFAMTransformer(model_config)
            trainer = Trainer(
                model,
                training_config,
                device=args.device,
                data_fingerprint=report.fingerprint,
                hardware_profile=profile,
                plan=plan,
            )
            if args.resume:
                resumed = load_checkpoint(
                    args.resume,
                    trainer,
                    tokenizer,
                    expected_data_fingerprint=report.fingerprint,
                )
                print(f"Resumed from step {resumed['global_step']}")
            print(f"Initialized {model.parameter_count():,} random parameters; no pretrained weights loaded.")
            print(f"Training plan: {json.dumps(plan.to_dict(), ensure_ascii=False)}")

            def batch_factory():
                # Derive the epoch seed from global_step so a resumed run does not
                # restart its shuffle sequence from the original seed.
                epoch_seed = training_config.seed + trainer.global_step
                return iter_batches(
                    args.corpus,
                    tokenizer,
                    split="train",
                    block_size=model_config.block_size,
                    batch_size=plan.micro_batch_size,
                    shuffle=True,
                    seed=epoch_seed,
                )

            def report_step(result):
                print(f"step={result.step} loss={result.loss:.4f} lr={result.learning_rate:.6g}")
                return True

            trainer.fit(
                batch_factory,
                max_steps=args.steps,
                checkpoint_path=str(args.output),
                checkpoint_interval_steps=training_config.checkpoint_interval_steps,
                tokenizer=tokenizer,
                on_step=report_step,
            )
            print(f"Training complete: {trainer.global_step} optimizer steps; checkpoint: {args.output}")
            validation_factory = lambda: iter_batches(
                args.corpus,
                tokenizer,
                split="validation",
                block_size=model_config.block_size,
                batch_size=plan.micro_batch_size,
            )
            if report.records_by_split["validation"]:
                metrics = Trainer.evaluate(model, validation_factory, device=trainer.device)
                print(f"Validation: {json.dumps(metrics)}")
            else:
                print("No validation split found; held-out evaluation was skipped.")
            return 0 if trainer.global_step >= args.steps else 1
        except (OSError, ValueError, RuntimeError, FloatingPointError) as exc:
            print(f"Training stopped safely: {exc}", file=sys.stderr)
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
