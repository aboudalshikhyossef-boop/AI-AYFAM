"""Command-line entry points for corpus preparation and AI AYFAM model training."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from model_factory.config import ModelConfig, TrainingConfig
from model_factory.corpus_tools import prepare_corpus, validate_prepared_corpus
from model_factory.data import iter_batches, iter_records, validate_corpus
from model_factory.hardware import HardwareProfile, build_training_plan
from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer, load_tokenizer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ayfam-model", description="AI AYFAM from-scratch model tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("profile", help="show a hardware-aware CPU training plan")

    validate = commands.add_parser("validate-corpus", help="validate the base provenance-aware JSONL schema")
    validate.add_argument("corpus", type=Path)

    audit = commands.add_parser("audit-prepared-corpus", help="verify group isolation, deduplication and held-out splits")
    audit.add_argument("corpus", type=Path)
    audit.add_argument("--allow-empty-held-out", action="store_true")

    prepare = commands.add_parser("prepare-corpus", help="normalize, deduplicate and split raw JSONL data")
    prepare.add_argument("input", type=Path)
    prepare.add_argument("output", type=Path)
    prepare.add_argument("--seed", type=int, default=42)
    prepare.add_argument("--train-ratio", type=float, default=0.90)
    prepare.add_argument("--validation-ratio", type=float, default=0.05)
    prepare.add_argument("--test-ratio", type=float, default=0.05)
    prepare.add_argument("--require-held-out", action="store_true")

    train_tokenizer = commands.add_parser("train-tokenizer", help="learn a byte-level BPE tokenizer from train split only")
    train_tokenizer.add_argument("--corpus", type=Path, required=True)
    train_tokenizer.add_argument("--output", type=Path, default=Path("runs/tokenizer/ayfam-bpe.json"))
    train_tokenizer.add_argument("--vocab-size", type=int, default=1_024)
    train_tokenizer.add_argument("--min-frequency", type=int, default=2)
    train_tokenizer.add_argument("--max-unique-pieces", type=int, default=100_000)

    train = commands.add_parser("train", help="train the randomly initialized AI AYFAM Transformer")
    train.add_argument("--corpus", type=Path, required=True)
    train.add_argument("--output", type=Path, default=Path("runs/ayfam-3m/latest.pt"))
    train.add_argument("--steps", type=int, default=1_000)
    train.add_argument("--resume", type=Path)
    train.add_argument("--tokenizer-config", type=Path)
    train.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
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

        if args.command == "audit-prepared-corpus":
            report = validate_prepared_corpus(
                args.corpus,
                require_held_out=not args.allow_empty_held_out,
            )
            print(json.dumps({
                "path": report.path,
                "fingerprint": report.fingerprint,
                "records_by_split": report.records_by_split,
                "total_records": report.total_records,
                "group_and_duplicate_checks": "passed",
            }, ensure_ascii=False, indent=2))
            return 0

        if args.command == "prepare-corpus":
            report = prepare_corpus(
                args.input,
                args.output,
                seed=args.seed,
                train_ratio=args.train_ratio,
                validation_ratio=args.validation_ratio,
                test_ratio=args.test_ratio,
                require_held_out=args.require_held_out,
            )
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
            return 0

        if args.command == "train-tokenizer":
            validate_prepared_corpus(args.corpus, require_held_out=True)
            tokenizer = ByteBPETokenizer.train_from_iterator(
                (record.text for record in iter_records(args.corpus, split="train")),
                vocab_size=args.vocab_size,
                min_frequency=args.min_frequency,
                max_unique_pieces=args.max_unique_pieces,
            )
            tokenizer.save(args.output)
            print(json.dumps({
                "tokenizer": str(args.output),
                "type": "utf8-byte-bpe",
                "vocab_size": tokenizer.vocab_size,
                "learned_merges": len(tokenizer.merges),
                "source_split": "train",
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

            report = validate_prepared_corpus(args.corpus, require_held_out=True)
            profile = HardwareProfile.detect()
            plan = build_training_plan(profile)
            tokenizer = (
                load_tokenizer(args.tokenizer_config)
                if args.tokenizer_config else ByteTokenizer()
            )
            model_config = ModelConfig(vocab_size=tokenizer.vocab_size)
            training_config = TrainingConfig(
                max_steps=args.steps,
                batch_size=plan.micro_batch_size,
                gradient_accumulation_steps=plan.gradient_accumulation_steps,
                checkpoint_interval_steps=plan.checkpoint_interval_steps,
                num_threads=plan.num_threads,
            )
            torch.manual_seed(training_config.seed)
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
            print(f"Tokenizer vocabulary: {tokenizer.vocab_size}")
            print(f"Training plan: {json.dumps(plan.to_dict(), ensure_ascii=False)}")

            def batch_factory():
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
            metrics = Trainer.evaluate(model, validation_factory, device=trainer.device)
            print(f"Validation: {json.dumps(metrics)}")
            return 0 if trainer.global_step >= args.steps else 1
    except (OSError, ValueError, RuntimeError, FloatingPointError) as exc:
        print(f"Model factory operation failed safely: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
