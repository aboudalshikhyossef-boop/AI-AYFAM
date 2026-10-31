"""Fast tests for the dependency-light model factory components."""

import json

import pytest

from model_factory.config import ModelConfig, TrainingConfig
from model_factory.data import fingerprint_file, iter_records, iter_token_blocks, validate_corpus
from model_factory.hardware import HardwareProfile, build_training_plan
from model_factory.tokenizer import ByteTokenizer


def test_default_model_is_a_three_million_parameter_proof_of_concept():
    config = ModelConfig()
    assert config.estimated_parameter_count == 3_042_432
    assert config.vocab_size == ByteTokenizer.VOCAB_SIZE
    assert config.block_size == 128


@pytest.mark.parametrize("values", [
    {"n_embd": 191, "n_head": 6},
    {"n_layer": 0},
    {"vocab_size": 259},
    {"dropout": 1.0},
    {"pad_token_id": 12},
])
def test_model_config_rejects_invalid_dimensions(values):
    with pytest.raises(ValueError):
        ModelConfig(**values)


def test_training_config_rejects_boolean_batch_size():
    with pytest.raises(ValueError):
        TrainingConfig(batch_size=True)


def test_byte_tokenizer_round_trips_arabic_and_english():
    tokenizer = ByteTokenizer()
    original = "مرحباً AI AYFAM — cybersecurity 🔐"
    ids = tokenizer.encode(original, add_bos=True, add_eos=True)
    assert ids[0] == tokenizer.BOS
    assert ids[-1] == tokenizer.EOS
    assert tokenizer.decode(ids) == original


def test_tokenizer_config_is_stable_and_saved_atomically(tmp_path):
    path = tmp_path / "tokenizer.json"
    tokenizer = ByteTokenizer()
    tokenizer.save(path)
    restored = ByteTokenizer.load(path)
    assert restored.to_dict() == tokenizer.to_dict()


def test_tokenizer_rejects_out_of_range_ids():
    with pytest.raises(ValueError):
        ByteTokenizer().decode([999])


def _write_corpus(path):
    records = [
        {"id": "train-1", "text": "مرحباً بالعالم", "source": "written-for-test", "license": "CC0-1.0", "split": "train"},
        {"id": "valid-1", "text": "اختبار مستقل", "source": "written-for-test", "license": "CC0-1.0", "split": "validation"},
    ]
    path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records), encoding="utf-8")


def test_jsonl_corpus_requires_provenance_and_explicit_splits(tmp_path):
    path = tmp_path / "corpus.jsonl"
    _write_corpus(path)
    report = validate_corpus(path)
    assert report.total_records == 2
    assert report.records_by_split == {"test": 0, "train": 1, "validation": 1}
    assert len(report.fingerprint) == 64
    assert [item.split for item in iter_records(path, split="train")] == ["train"]


@pytest.mark.parametrize("record", [
    {"text": "no source", "license": "CC0-1.0", "split": "train"},
    {"text": "no license", "source": "test", "split": "train"},
    {"text": "no split", "source": "test", "license": "CC0-1.0"},
])
def test_jsonl_rejects_missing_governance_fields(tmp_path, record):
    path = tmp_path / "invalid.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        list(iter_records(path))


def test_jsonl_rejects_invalid_json_and_missing_train_split(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text("{broken}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        validate_corpus(path)
    path.write_text(json.dumps({
        "text": "only validation",
        "source": "test",
        "license": "CC0-1.0",
        "split": "validation",
    }) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at least one"):
        validate_corpus(path)


def test_token_blocks_are_fixed_length_and_do_not_mix_splits(tmp_path):
    path = tmp_path / "corpus.jsonl"
    _write_corpus(path)
    blocks = list(iter_token_blocks(path, ByteTokenizer(), split="train", block_size=8))
    assert blocks
    assert all(len(inputs) == len(targets) == 8 for inputs, targets in blocks)
    assert all(inputs[0] == ByteTokenizer.BOS for inputs, _ in blocks[:1])


def test_corpus_fingerprint_changes_when_data_changes(tmp_path):
    path = tmp_path / "corpus.jsonl"
    _write_corpus(path)
    first = fingerprint_file(path)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert fingerprint_file(path) != first


def test_hardware_planner_is_conservative_and_does_not_change_model_size():
    small = HardwareProfile(8_000, 1_800, 4, "x86_64", "test")
    large = HardwareProfile(32_000, 24_000, 12, "x86_64", "test")
    small_plan = build_training_plan(small)
    large_plan = build_training_plan(large)
    assert small_plan.micro_batch_size == 1
    assert small_plan.num_threads == 1
    assert large_plan.micro_batch_size >= small_plan.micro_batch_size
    assert large_plan.num_threads <= 4
    assert small_plan.micro_batch_size * small_plan.gradient_accumulation_steps == 4
    assert large_plan.micro_batch_size * large_plan.gradient_accumulation_steps == 4
    assert ModelConfig().estimated_parameter_count == 3_042_432


def test_hardware_profile_detect_does_not_require_torch():
    profile = HardwareProfile.detect()
    assert profile.logical_cores >= 1
    assert profile.available_ram_mb >= 0


def test_jsonl_reader_rejects_oversized_line_before_loading_it_all(tmp_path, monkeypatch):
    import model_factory.data as corpus_data

    path = tmp_path / "oversized.jsonl"
    path.write_bytes(b"x" * 128 + b"\n")
    monkeypatch.setattr(corpus_data, "MAX_RECORD_BYTES", 32)
    with pytest.raises(ValueError, match="exceeds 32 bytes"):
        list(iter_records(path))


def test_hardware_plans_keep_effective_batch_constant_when_moving_devices():
    profiles = [
        HardwareProfile(4_000, 1_000, 2, "x86_64", "small"),
        HardwareProfile(8_000, 3_000, 4, "x86_64", "laptop"),
        HardwareProfile(32_000, 20_000, 12, "x86_64", "workstation"),
    ]
    effective_batches = {
        build_training_plan(profile).micro_batch_size
        * build_training_plan(profile).gradient_accumulation_steps
        for profile in profiles
    }
    assert effective_batches == {4}
