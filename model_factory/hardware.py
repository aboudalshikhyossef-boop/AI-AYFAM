"""Low-cost hardware profiling and conservative training-plan selection."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import platform


def _read_meminfo_mb() -> tuple[int, int]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                values[key] = int(parts[0]) // 1024
    except OSError:
        pass
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    return total, available


def _cgroup_memory_limit_mb() -> int | None:
    candidates = (
        (Path("/sys/fs/cgroup/memory.max"), Path("/sys/fs/cgroup/memory.current")),
        (Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
         Path("/sys/fs/cgroup/memory/memory.usage_in_bytes")),
    )
    for limit_path, usage_path in candidates:
        try:
            raw_limit = limit_path.read_text(encoding="ascii").strip()
            raw_usage = usage_path.read_text(encoding="ascii").strip()
            if raw_limit == "max":
                continue
            limit, usage = int(raw_limit), int(raw_usage)
            if 0 < limit < (1 << 60):
                return max(0, min(limit, limit - usage) // (1024 * 1024))
        except (OSError, ValueError):
            continue
    return None


@dataclass(frozen=True)
class HardwareProfile:
    total_ram_mb: int
    available_ram_mb: int
    logical_cores: int
    architecture: str
    platform_name: str
    cuda_device_detected: bool = False

    def __post_init__(self) -> None:
        for field_name in ("total_ram_mb", "available_ram_mb", "logical_cores"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.logical_cores < 1:
            raise ValueError("logical_cores must be at least 1")

    @classmethod
    def detect(cls) -> "HardwareProfile":
        total, available = _read_meminfo_mb()
        cgroup_available = _cgroup_memory_limit_mb()
        if cgroup_available is not None:
            available = min(available, cgroup_available) if available else cgroup_available
        try:
            cores = len(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            cores = os.cpu_count() or 1
        return cls(
            total_ram_mb=max(0, total),
            available_ram_mb=max(0, available),
            logical_cores=max(1, cores),
            architecture=platform.machine() or "unknown",
            platform_name=platform.platform(),
            cuda_device_detected=Path("/dev/nvidia0").exists(),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TrainingPlan:
    micro_batch_size: int
    gradient_accumulation_steps: int
    num_threads: int
    checkpoint_interval_steps: int
    memory_budget_mb: int
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["notes"] = list(self.notes)
        return result


def build_training_plan(profile: HardwareProfile) -> TrainingPlan:
    """Choose optimizer throughput settings; never mutate the model architecture."""
    available = profile.available_ram_mb
    if available <= 2_048:
        batch, accumulation, threads, interval = 1, 4, 1, 50
        memory_budget = max(256, int(available * 0.20))
        note = (
            "Very low or unknown available memory: single-sample batches and one CPU thread."
            if available == 0 else
            "Very low available memory: single-sample batches and one CPU thread."
        )
    elif available <= 4_096:
        batch, accumulation, threads, interval = 1, 4, min(2, profile.logical_cores), 75
        memory_budget = max(384, int(available * 0.20))
        note = "Low-memory profile: conservative accumulation and frequent checkpoints."
    elif available and available <= 8_192:
        batch, accumulation, threads, interval = 1, 4, min(2, profile.logical_cores), 100
        memory_budget = int(available * 0.20)
        note = "Typical 8 GB-class profile: micro-batch 1; optimizer accumulation 4."
    else:
        batch, accumulation, threads, interval = 2, 2, min(4, profile.logical_cores), 200
        memory_budget = int(available * 0.20) if available else 1_024
        note = "More memory available: modestly increase micro-batch size."
    return TrainingPlan(
        micro_batch_size=batch,
        gradient_accumulation_steps=accumulation,
        num_threads=max(1, threads),
        checkpoint_interval_steps=interval,
        memory_budget_mb=max(256, memory_budget),
        notes=(note, "The model dimensions remain fixed; only runtime settings are adapted."),
    )
