"""CPU-first training loop for the AI AYFAM from-scratch Transformer."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
import math
from typing import Any

from model_factory.config import TrainingConfig
from model_factory.hardware import HardwareProfile, TrainingPlan, build_training_plan


@dataclass(frozen=True)
class StepResult:
    step: int
    loss: float
    learning_rate: float


class Trainer:
    def __init__(
        self,
        model,
        config: TrainingConfig | None = None,
        *,
        device: str = "auto",
        data_fingerprint: str = "",
        hardware_profile: HardwareProfile | None = None,
        plan: TrainingPlan | None = None,
    ):
        try:
            import torch
        except ImportError as exc:
            raise RuntimeError(
                "PyTorch is optional. Install requirements-training.txt to train AYFAM."
            ) from exc
        self.torch = torch
        self.config = config or TrainingConfig()
        self.hardware_profile = hardware_profile or HardwareProfile.detect()
        self.plan = plan or build_training_plan(self.hardware_profile)
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"
        if device.startswith("cuda") and not torch.cuda.is_available():
            raise RuntimeError("CUDA was requested but is not available in this PyTorch build")
        self.device = torch.device(device)
        self.model = model.to(self.device)
        self.data_fingerprint = data_fingerprint
        self.global_step = 0
        self.torch.set_num_threads(self.config.num_threads if config else self.plan.num_threads)
        torch.manual_seed(self.config.seed)
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )

    def _learning_rate(self, step: int) -> float:
        if self.config.warmup_steps and step < self.config.warmup_steps:
            scale = (step + 1) / self.config.warmup_steps
        else:
            denominator = max(1, self.config.max_steps - self.config.warmup_steps)
            progress = min(1.0, max(0.0, (step - self.config.warmup_steps) / denominator))
            scale = 0.5 * (1.0 + math.cos(math.pi * progress))
        return self.config.learning_rate * scale

    def _optimizer_step(self, actual_accumulation: int, *, normalize_partial: bool = True) -> None:
        if actual_accumulation <= 0:
            return
        if normalize_partial and actual_accumulation != self.config.gradient_accumulation_steps:
            scale = self.config.gradient_accumulation_steps / actual_accumulation
            for parameter in self.model.parameters():
                if parameter.grad is not None:
                    parameter.grad.mul_(scale)
        self.torch.nn.utils.clip_grad_norm_(
            self.model.parameters(), self.config.gradient_clip_norm
        )
        learning_rate = self._learning_rate(self.global_step)
        for group in self.optimizer.param_groups:
            group["lr"] = learning_rate
        self.optimizer.step()
        self.optimizer.zero_grad(set_to_none=True)
        self.global_step += 1

    def train_batch(self, input_ids, targets) -> StepResult:
        """Perform one optimizer step; useful for smoke tests and custom data sources."""
        self.model.train()
        input_ids = input_ids.to(self.device)
        targets = targets.to(self.device)
        self.optimizer.zero_grad(set_to_none=True)
        output = self.model(input_ids, targets)
        loss = output["loss"]
        if loss is None or not bool(self.torch.isfinite(loss)):
            raise FloatingPointError("training loss is missing or non-finite")
        loss.backward()
        self._optimizer_step(1, normalize_partial=False)
        return StepResult(
            step=self.global_step,
            loss=float(loss.detach().cpu()),
            learning_rate=float(self.optimizer.param_groups[0]["lr"]),
        )

    def fit(
        self,
        batch_factory: Callable[[], Iterable[tuple[Any, Any]]],
        *,
        max_steps: int | None = None,
        checkpoint_path: str | None = None,
        checkpoint_interval_steps: int | None = None,
        tokenizer=None,
        on_step: Callable[[StepResult], bool | None] | None = None,
    ) -> list[StepResult]:
        """Train until max_steps; batch_factory is re-opened for each data epoch."""
        from model_factory.checkpoint import save_checkpoint

        target_steps = max_steps if max_steps is not None else self.config.max_steps
        if isinstance(target_steps, bool) or not isinstance(target_steps, int) or target_steps <= 0:
            raise ValueError("max_steps must be a positive integer")
        interval = (
            self.config.checkpoint_interval_steps
            if checkpoint_interval_steps is None
            else checkpoint_interval_steps
        )
        if isinstance(interval, bool) or not isinstance(interval, int) or interval <= 0:
            raise ValueError("checkpoint_interval_steps must be a positive integer")
        if checkpoint_path and tokenizer is None:
            raise ValueError("tokenizer is required when checkpointing is enabled")
        # Keep only a recent window; long CPU runs must not retain every step in RAM.
        history: deque[StepResult] = deque(maxlen=1_000)
        while self.global_step < target_steps:
            saw_batch = False
            accumulated = 0
            accumulated_loss = 0.0
            self.model.train()
            self.optimizer.zero_grad(set_to_none=True)
            for input_ids, targets in batch_factory():
                saw_batch = True
                input_ids = input_ids.to(self.device)
                targets = targets.to(self.device)
                output = self.model(input_ids, targets)
                loss = output["loss"]
                if loss is None or not bool(self.torch.isfinite(loss)):
                    raise FloatingPointError("training loss is missing or non-finite")
                (loss / self.config.gradient_accumulation_steps).backward()
                accumulated += 1
                accumulated_loss += float(loss.detach().cpu())
                if accumulated == self.config.gradient_accumulation_steps:
                    self._optimizer_step(accumulated)
                    result = StepResult(
                        step=self.global_step,
                        loss=accumulated_loss / accumulated,
                        learning_rate=float(self.optimizer.param_groups[0]["lr"]),
                    )
                    history.append(result)
                    accumulated = 0
                    accumulated_loss = 0.0
                    if on_step is not None and on_step(result) is False:
                        if checkpoint_path:
                            save_checkpoint(checkpoint_path, self, tokenizer)
                        return list(history)
                    if checkpoint_path and self.global_step % interval == 0:
                        save_checkpoint(checkpoint_path, self, tokenizer)
                    if self.global_step >= target_steps:
                        break
            if not saw_batch:
                raise ValueError("training corpus produced no usable token batches")
            if accumulated and self.global_step < target_steps:
                self._optimizer_step(accumulated)
                result = StepResult(
                    step=self.global_step,
                    loss=accumulated_loss / accumulated,
                    learning_rate=float(self.optimizer.param_groups[0]["lr"]),
                )
                history.append(result)
                if on_step is not None and on_step(result) is False:
                    if checkpoint_path:
                        save_checkpoint(checkpoint_path, self, tokenizer)
                    return list(history)
                if checkpoint_path and self.global_step % interval == 0:
                    save_checkpoint(checkpoint_path, self, tokenizer)
        if checkpoint_path:
            save_checkpoint(checkpoint_path, self, tokenizer)
        return list(history)

    @staticmethod
    def evaluate(model, batch_factory: Callable[[], Iterable[tuple[Any, Any]]], device="cpu") -> dict[str, float]:
        try:
            import torch
        except ImportError as exc:
            raise RuntimeError("PyTorch is required for model evaluation") from exc
        was_training = model.training
        model.eval()
        total_loss = 0.0
        batches = 0
        try:
            with torch.no_grad():
                for input_ids, targets in batch_factory():
                    output = model(input_ids.to(device), targets.to(device))
                    loss = output["loss"]
                    if loss is not None and bool(torch.isfinite(loss)):
                        total_loss += float(loss.cpu())
                        batches += 1
        finally:
            model.train(was_training)
        if batches == 0:
            raise ValueError("validation corpus produced no usable batches")
        average = total_loss / batches
        return {"loss": average, "perplexity": math.exp(min(average, 20.0))}
