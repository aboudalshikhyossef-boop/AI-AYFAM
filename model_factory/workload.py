"""Data-size and hardware-aware planning for complete local training passes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from pathlib import Path

from model_factory.data import iter_records
from model_factory.hardware import HardwareProfile, TrainingPlan
from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer


@dataclass(frozen=True)
class TrainingWorkloadPlan:
    train_records: int
    train_utf8_bytes: int
    train_tokens: int
    train_blocks_per_epoch: int
    batches_per_epoch: int
    optimizer_steps_per_epoch: int
    epochs: int
    additional_steps: int
    target_global_step: int
    block_size: int
    micro_batch_size: int
    gradient_accumulation_steps: int
    tokenizer_vocab_size: int
    tokenizer_vocab_reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def recommend_tokenizer_vocab_size(
    train_utf8_bytes: int,
    profile: HardwareProfile,
) -> tuple[int, str]:
    """Choose a conservative BPE vocabulary target from corpus volume and RAM.

    This is a target, not a promise that every slot will be learned. BPE stops
    early when the source corpus no longer contains sufficiently frequent pairs.
    """
    if isinstance(train_utf8_bytes, bool) or not isinstance(train_utf8_bytes, int) or train_utf8_bytes < 0:
        raise ValueError("train_utf8_bytes must be a non-negative integer")

    if train_utf8_bytes < 100_000:
        data_target = 320
        data_reason = "small corpus"
    elif train_utf8_bytes < 750_000:
        data_target = 512
        data_reason = "medium corpus"
    elif train_utf8_bytes < 4_000_000:
        data_target = 768
        data_reason = "large corpus"
    else:
        data_target = 1_024
        data_reason = "very large corpus"

    available = profile.available_ram_mb
    if available <= 2_048:
        ram_cap = 384
    elif available <= 4_096:
        ram_cap = 512
    elif available <= 8_192:
        ram_cap = 768
    else:
        ram_cap = 1_024

    target = max(ByteBPETokenizer.BASE_VOCAB_SIZE, min(data_target, ram_cap))
    reason = (
        f"{data_reason}: {train_utf8_bytes:,} UTF-8 bytes; "
        f"available RAM {available:,} MB; target capped at {target} entries"
    )
    return target, reason



def measure_train_data_bytes(corpus_path: str | Path) -> tuple[int, int]:
    """Count train records and UTF-8 bytes with bounded memory."""
    records = 0
    byte_count = 0
    for record in iter_records(corpus_path, split="train"):
        records += 1
        byte_count += len(record.text.encode("utf-8"))
    if records == 0:
        raise ValueError("the train split is empty")
    return records, byte_count

def count_training_workload(
    corpus_path: str | Path,
    tokenizer: ByteTokenizer | ByteBPETokenizer,
    *,
    profile: HardwareProfile,
    runtime_plan: TrainingPlan,
    block_size: int,
    epochs: int,
    starting_step: int = 0,
    tokenizer_vocab_reason: str = "user-supplied tokenizer",
) -> TrainingWorkloadPlan:
    """Count every train-split token block without materializing the corpus."""
    if isinstance(block_size, bool) or not isinstance(block_size, int) or block_size <= 0:
        raise ValueError("block_size must be a positive integer")
    if isinstance(epochs, bool) or not isinstance(epochs, int) or not 1 <= epochs <= 100:
        raise ValueError("epochs must be an integer between 1 and 100")
    if isinstance(starting_step, bool) or not isinstance(starting_step, int) or starting_step < 0:
        raise ValueError("starting_step must be a non-negative integer")

    train_records = 0
    train_utf8_bytes = 0
    train_tokens = 0
    train_blocks = 0
    for record in iter_records(corpus_path, split="train"):
        train_records += 1
        train_utf8_bytes += len(record.text.encode("utf-8"))
        encoded = tokenizer.encode(record.text, add_bos=True, add_eos=True)
        usable_targets = max(0, len(encoded) - 1)
        train_tokens += usable_targets
        if usable_targets:
            train_blocks += math.ceil(usable_targets / block_size)

    if train_records == 0 or train_blocks == 0:
        raise ValueError("the train split contains no usable token blocks")

    batches_per_epoch = math.ceil(train_blocks / runtime_plan.micro_batch_size)
    steps_per_epoch = math.ceil(
        batches_per_epoch / runtime_plan.gradient_accumulation_steps
    )
    target_vocab, default_reason = recommend_tokenizer_vocab_size(train_utf8_bytes, profile)
    if isinstance(tokenizer, ByteBPETokenizer):
        actual_vocab = tokenizer.vocab_size
    else:
        actual_vocab = tokenizer.vocab_size
    return TrainingWorkloadPlan(
        train_records=train_records,
        train_utf8_bytes=train_utf8_bytes,
        train_tokens=train_tokens,
        train_blocks_per_epoch=train_blocks,
        batches_per_epoch=batches_per_epoch,
        optimizer_steps_per_epoch=steps_per_epoch,
        epochs=epochs,
        additional_steps=steps_per_epoch * epochs,
        target_global_step=starting_step + steps_per_epoch * epochs,
        block_size=block_size,
        micro_batch_size=runtime_plan.micro_batch_size,
        gradient_accumulation_steps=runtime_plan.gradient_accumulation_steps,
        tokenizer_vocab_size=actual_vocab,
        tokenizer_vocab_reason=tokenizer_vocab_reason or default_reason,
    )
