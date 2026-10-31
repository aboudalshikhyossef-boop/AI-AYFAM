"""Command-line entry points for corpus, tokenizer, training and local inference tools."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from model_factory.corpus_tools import prepare_corpus, validate_prepared_corpus
from model_factory.data import iter_records, validate_corpus
from model_factory.hardware import HardwareProfile, build_training_plan
from model_factory.tokenizer import ByteBPETokenizer
from model_factory.runner import TrainingRunConfig, run_training


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

    export_model = commands.add_parser("export-model", help="export compact model-only weights from a training checkpoint")
    export_model.add_argument("--checkpoint", type=Path, required=True)
    export_model.add_argument("--output", type=Path, default=Path("runs/ayfam-3m/inference.pt"))

    generate = commands.add_parser("generate", help="generate a local continuation from an exported model")
    generate.add_argument("--model", type=Path, required=True)
    generate.add_argument("--prompt", required=True)
    generate.add_argument("--max-new-tokens", type=int, default=64)
    generate.add_argument("--temperature", type=float, default=0.8)
    generate.add_argument("--top-k", type=int, default=40, help="use 0 to disable top-k")
    generate.add_argument("--top-p", type=float, default=0.9, help="use 1.0 to disable nucleus filtering")
    generate.add_argument("--seed", type=int, default=42)
    generate.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")

    evaluate = commands.add_parser("evaluate", help="evaluate an exported model on held-out validation or test data")
    evaluate.add_argument("--model", type=Path, required=True)
    evaluate.add_argument("--corpus", type=Path, required=True)
    evaluate.add_argument("--split", choices=("validation", "test"), default="test")
    evaluate.add_argument("--batch-size", type=int, default=1)
    evaluate.add_argument("--max-batches", type=int)
    evaluate.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")

    benchmark = commands.add_parser("benchmark", help="measure local inference speed and peak memory")
    benchmark.add_argument("--model", type=Path, required=True)
    benchmark.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    benchmark.add_argument("--threads", type=int)
    benchmark.add_argument("--batch-size", type=int, default=1)
    benchmark.add_argument("--sequence-length", type=int)
    benchmark.add_argument("--warmup", type=int, default=2)
    benchmark.add_argument("--iterations", type=int, default=10)
    benchmark.add_argument("--generation-tokens", type=int, default=16)

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
            if args.steps <= 0:
                print("--steps must be positive", file=sys.stderr)
                return 2

            def report_step(result):
                print(f"step={result.step} loss={result.loss:.4f} lr={result.learning_rate:.6g}")
                return True

            result = run_training(
                TrainingRunConfig(
                    corpus_path=args.corpus,
                    checkpoint_path=args.output,
                    max_steps=args.steps,
                    device=args.device,
                    tokenizer_config_path=args.tokenizer_config,
                    resume_checkpoint=args.resume,
                ),
                on_step=report_step,
            )
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
            return 0 if result.completed_steps >= args.steps else 1

        if args.command == "export-model":
            from model_factory.inference import export_inference_artifact
            destination = export_inference_artifact(args.checkpoint, args.output)
            print(json.dumps({"model_artifact": str(destination)}, ensure_ascii=False, indent=2))
            return 0

        if args.command == "generate":
            from model_factory.inference import generate_text, load_inference_model
            loaded = load_inference_model(args.model, device=args.device)
            result = generate_text(
                loaded,
                args.prompt,
                max_new_tokens=args.max_new_tokens,
                temperature=args.temperature,
                top_k=None if args.top_k == 0 else args.top_k,
                top_p=None if args.top_p == 1.0 else args.top_p,
                seed=args.seed,
            )
            print(json.dumps({
                "text": result.text,
                "prompt_tokens": result.prompt_token_count,
                "generated_tokens": result.generated_token_count,
                "stopped_on_eos": result.stopped_on_eos,
                "model_parameters": loaded.model.parameter_count(),
                "device": loaded.device,
            }, ensure_ascii=False, indent=2))
            return 0

        if args.command == "evaluate":
            from model_factory.evaluation import evaluate_model
            from model_factory.inference import load_inference_model
            loaded = load_inference_model(args.model, device=args.device)
            metrics = evaluate_model(
                loaded,
                str(args.corpus),
                split=args.split,
                batch_size=args.batch_size,
                max_batches=args.max_batches,
            )
            print(json.dumps(metrics, ensure_ascii=False, indent=2))
            return 0

        if args.command == "benchmark":
            from model_factory.benchmark import benchmark_model
            from model_factory.inference import load_inference_model
            loaded = load_inference_model(args.model, device=args.device)
            profile = HardwareProfile.detect()
            plan = build_training_plan(profile)
            metrics = benchmark_model(
                loaded,
                batch_size=args.batch_size,
                sequence_length=args.sequence_length,
                warmup_iterations=args.warmup,
                iterations=args.iterations,
                generation_tokens=args.generation_tokens,
                threads=plan.num_threads if args.threads is None else args.threads,
            )
            print(json.dumps(metrics, ensure_ascii=False, indent=2))
            return 0
    except Exception as exc:
        print(f"Model factory operation failed safely: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
