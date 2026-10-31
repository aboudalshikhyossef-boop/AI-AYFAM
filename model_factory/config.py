"""Validated, serializable configuration for the first AI AYFAM language model."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any


@dataclass(frozen=True)
class ModelConfig:
    """Small decoder-only Transformer configuration, initialized from random weights."""

    vocab_size: int = 260
    block_size: int = 128
    n_layer: int = 8
    n_head: int = 6
    n_embd: int = 192
    ffn_dim: int = 576
    dropout: float = 0.0
    pad_token_id: int = 256
    eos_token_id: int = 258
    tie_embeddings: bool = True

    def __post_init__(self) -> None:
        integer_fields = (
            "vocab_size", "block_size", "n_layer", "n_head", "n_embd",
            "ffn_dim", "pad_token_id", "eos_token_id",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.n_embd % self.n_head:
            raise ValueError("n_embd must be divisible by n_head")
        if self.vocab_size <= 259:
            raise ValueError("vocab_size must include all 260 byte and special tokens")
        if self.pad_token_id < 256 or self.eos_token_id < 256:
            raise ValueError("special token IDs must not overlap UTF-8 byte IDs")
        if self.pad_token_id >= self.vocab_size or self.eos_token_id >= self.vocab_size:
            raise ValueError("special token IDs must be smaller than vocab_size")
        if self.pad_token_id == self.eos_token_id:
            raise ValueError("pad_token_id and eos_token_id must be different")
        if isinstance(self.dropout, bool) or not isinstance(self.dropout, (float, int)):
            raise ValueError("dropout must be a number between 0 and 1")
        if not math.isfinite(float(self.dropout)) or not 0.0 <= float(self.dropout) < 1.0:
            raise ValueError("dropout must be a finite number between 0 and 1")
        if not isinstance(self.tie_embeddings, bool):
            raise ValueError("tie_embeddings must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> "ModelConfig":
        if not isinstance(values, dict):
            raise TypeError("model configuration must be a JSON object")
        return cls(**values)

    @property
    def estimated_parameter_count(self) -> int:
        """Exact count for the bundled tied-weight Transformer implementation."""
        d = self.n_embd
        attention_and_mlp = 4 * d * d + 2 * d * self.ffn_dim + 9 * d + self.ffn_dim
        token_embeddings = self.vocab_size * d
        position_embeddings = self.block_size * d
        final_norm = 2 * d
        output_head = 0 if self.tie_embeddings else self.vocab_size * d
        return token_embeddings + position_embeddings + self.n_layer * attention_and_mlp + final_norm + output_head


@dataclass(frozen=True)
class TrainingConfig:
    """Conservative optimizer settings; the hardware planner may lower batch size."""

    max_steps: int = 1_000
    batch_size: int = 1
    gradient_accumulation_steps: int = 4
    learning_rate: float = 3e-4
    weight_decay: float = 0.1
    gradient_clip_norm: float = 1.0
    warmup_steps: int = 50
    checkpoint_interval_steps: int = 100
    num_threads: int = 2
    seed: int = 42

    def __post_init__(self) -> None:
        for name in (
            "max_steps", "batch_size", "gradient_accumulation_steps",
            "checkpoint_interval_steps", "num_threads",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.warmup_steps, bool) or not isinstance(self.warmup_steps, int):
            raise ValueError("warmup_steps must be a non-negative integer")
        if self.warmup_steps < 0:
            raise ValueError("warmup_steps must be a non-negative integer")
        for name in ("learning_rate", "weight_decay", "gradient_clip_norm"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a finite positive number")
            if not math.isfinite(float(value)) or value < 0:
                raise ValueError(f"{name} must be a finite non-negative number")
        if self.learning_rate <= 0 or self.gradient_clip_norm <= 0:
            raise ValueError("learning_rate and gradient_clip_norm must be positive")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
