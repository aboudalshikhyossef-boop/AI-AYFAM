"""Tests for learned, versioned byte-level BPE tokenization."""

import pytest

from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer, load_tokenizer


def _texts():
    return [
        "الذكاء الاصطناعي والأمن السيبراني",
        "الذكاء الاصطناعي والأمن السيبراني",
        "AI AYFAM cybersecurity model training",
        "AI AYFAM cybersecurity model training",
        "تحليل الشبكات واكتشاف التهديدات",
        "تحليل الشبكات واكتشاف التهديدات",
    ]


def test_bpe_learns_merges_and_round_trips_arabic_english_and_symbols():
    tokenizer = ByteBPETokenizer.train_from_iterator(
        _texts(), vocab_size=360, min_frequency=2
    )
    sample = "مرحباً AI AYFAM — cybersecurity 🔐\nاختبار"
    encoded = tokenizer.encode(sample, add_bos=True, add_eos=True)
    assert tokenizer.merges
    assert any(
        token_id >= 260
        for training_text in _texts()
        for token_id in tokenizer.encode(training_text)
    )
    assert tokenizer.decode(tokenizer.encode(_texts()[0])) == _texts()[0]
    assert len(tokenizer._token_bytes) == tokenizer.vocab_size
    assert tokenizer.vocab_size == 260 + len(tokenizer.merges)
    assert encoded[0] == tokenizer.BOS
    assert encoded[-1] == tokenizer.EOS
    assert tokenizer.decode(encoded) == sample


def test_bpe_training_is_deterministic():
    first = ByteBPETokenizer.train_from_iterator(_texts(), vocab_size=340, min_frequency=2)
    second = ByteBPETokenizer.train_from_iterator(_texts(), vocab_size=340, min_frequency=2)
    assert first.to_dict() == second.to_dict()


def test_bpe_tokenizer_round_trips_save_and_load(tmp_path):
    tokenizer = ByteBPETokenizer.train_from_iterator(_texts(), vocab_size=330, min_frequency=2)
    path = tmp_path / "ayfam-bpe.json"
    tokenizer.save(path)
    restored = ByteBPETokenizer.load(path)
    sample = "تحليل AI AYFAM"
    assert restored.to_dict() == tokenizer.to_dict()
    assert restored.encode(sample) == tokenizer.encode(sample)
    assert restored.decode(restored.encode(sample)) == sample


def test_bpe_rejects_invalid_merge_references_and_vocab_size():
    payload = ByteBPETokenizer().to_dict()
    payload["merges"] = [[261, 1]]
    payload["vocab_size"] = 261
    with pytest.raises(ValueError, match="previously merged"):
        ByteBPETokenizer.from_dict(payload)

    payload = ByteBPETokenizer().to_dict()
    payload["vocab_size"] = 999
    with pytest.raises(ValueError, match="does not match"):
        ByteBPETokenizer.from_dict(payload)


@pytest.mark.parametrize("kwargs", [
    {"vocab_size": 259},
    {"vocab_size": True},
    {"min_frequency": 0},
    {"max_unique_pieces": -1},
])
def test_bpe_rejects_invalid_training_limits(kwargs):
    with pytest.raises(ValueError):
        ByteBPETokenizer.train_from_iterator(_texts(), **kwargs)


def test_bpe_requires_nonempty_training_texts():
    with pytest.raises(ValueError, match="empty text iterator"):
        ByteBPETokenizer.train_from_iterator([], vocab_size=300)


def test_original_byte_tokenizer_checkpoint_contract_is_unchanged():
    tokenizer = ByteTokenizer()
    assert tokenizer.to_dict() == {
        "schema_version": 1,
        "type": "utf8-byte",
        "vocab_size": 260,
        "special_tokens": {"pad": 256, "bos": 257, "eos": 258, "unk": 259},
    }
    assert tokenizer.vocab_size == 260



def test_tokenizer_loader_preserves_byte_and_loads_bpe_formats(tmp_path):
    byte_path = tmp_path / "byte.json"
    bpe_path = tmp_path / "bpe.json"
    ByteTokenizer().save(byte_path)
    learned = ByteBPETokenizer.train_from_iterator(_texts(), vocab_size=280, min_frequency=2)
    learned.save(bpe_path)

    assert isinstance(load_tokenizer(byte_path), ByteTokenizer)
    restored_bpe = load_tokenizer(bpe_path)
    assert isinstance(restored_bpe, ByteBPETokenizer)
    assert restored_bpe.to_dict() == learned.to_dict()
