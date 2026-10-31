# AI AYFAM — corpus preparation and Arabic/English BPE

This stage adds a reproducible path from raw, owner-authorized text to a clean
training corpus and a tokenizer learned from that corpus. It downloads no
training text, tokenizer vocabulary, or pretrained model.

## 1. Raw input format

Create a UTF-8 JSONL file outside the Git repository. Each line is one document
or document segment:

~~~json
{"id":"doc-a-001","group_id":"doc-a","text":"نص عربي مملوك للمشروع.","source":"project-authored:doc-a","license":"owner-permission","split":"train"}
{"id":"doc-b-001","group_id":"doc-b","text":"An independently authored English sample.","source":"project-authored:doc-b","license":"owner-permission","split":"validation"}
~~~

Required fields:
- text: non-empty text.
- source: provenance of the text.
- license: an SPDX license identifier or a documented owner-permission label.

Recommended metadata:
- group_id: stable ID for the original document/source group. If omitted, the
  source value is used as the group key. Give each independent source document
  its own source or group_id so unrelated documents are not tied together.
- split: optional. Either provide it on every input row, or omit it on every row.

The split value, when supplied, must be train, validation, or test. All chunks
from one group_id must stay in the same split. If group_id is omitted, source
is used as the grouping key. Do not use a generic source value for unrelated
documents: give each independent source document a unique group_id.

Do not place API keys, passwords, private keys, personal records, customer data,
host inventories, or sensitive scan results in the corpus. Only include material
whose owner has explicitly authorized model training or whose license permits
the intended use. A non-empty license label is recorded as provenance; the
tool does not provide legal advice or prove that the stated permission is valid.

## 2. Prepare and split the corpus

Install no extra packages for this step:

~~~bash
python -m model_factory.cli prepare-corpus \
  ~/ayfam-training-data/raw.jsonl \
  ~/ayfam-training-data/ayfam-prepared.jsonl \
  --seed 42 \
  --train-ratio 0.90 \
  --validation-ratio 0.05 \
  --test-ratio 0.05 \
  --require-held-out
~~~

If each source document should keep a pre-assigned split, include split on every
row and omit the ratios from the command. Explicit group conflicts are rejected.

The split is deterministic by group_id/source and seed, not by individual row.
The output is written atomically and restricted to the current user. The
preparation process:
- normalizes Unicode to NFC and line endings/spacing;
- preserves Arabic joining controls, while dropping other control/format chars;
- detects high-confidence credential patterns and refuses the corpus rather
  than copying matched secret material into the output;
- removes exact duplicates after normalization using a disk-backed SQLite index;
- rejects identical normalized text found in different splits;
- rejects a source group assigned to multiple splits;
- records an initial Arabic/English/mixed/other character-script summary;
- writes provenance, group ID, split and a SHA-256 corpus fingerprint.

Exact-deduplication does not detect paraphrases or every near-duplicate. The
language label is a lightweight Unicode-script heuristic, not a full language
detector. Credential scanning catches selected high-confidence patterns only;
it cannot guarantee that a corpus contains no secrets or personal information.
Review the source data manually before training.

For a small number of source groups, a random-looking stable split may leave
validation or test empty. Add more independent source documents or provide
explicit reviewed splits. Never split chunks from one source document across
train/validation/test to make the counts look balanced.

Validate the prepared data:

~~~bash
python -m model_factory.cli audit-prepared-corpus \
  ~/ayfam-training-data/ayfam-prepared.jsonl
~~~

## 3. Learn BPE from the train split only

~~~bash
python -m model_factory.cli train-tokenizer \
  --corpus ~/ayfam-training-data/ayfam-prepared.jsonl \
  --output ~/ayfam-training-data/ayfam-bpe.json \
  --vocab-size 1024 \
  --min-frequency 2
~~~

The tokenizer starts with the 256 raw UTF-8 byte IDs and the same four special
IDs used by the original byte tokenizer. It learns merge rules from records
marked train only; validation/test text is never used to learn vocabulary.
Whitespace is preserved and used as a pre-tokenization boundary. This is an
initial, transparent byte-BPE implementation, not a claim of matching GPT's
full pre-tokenization or optimized tokenizer throughput.

The tokenizer configuration stores its schema version, vocabulary size,
special-token IDs and ordered merge table. It can be copied with a checkpoint.
Do not edit or retrain the merge table for an existing checkpoint.

## 4. Train with the learned tokenizer

~~~bash
python -m model_factory.cli train \
  --corpus ~/ayfam-training-data/ayfam-prepared.jsonl \
  --tokenizer-config ~/ayfam-training-data/ayfam-bpe.json \
  --output runs/ayfam-bpe/latest.pt \
  --steps 1000
~~~

The model embedding size is derived from the loaded tokenizer vocabulary.
Checkpoint loading verifies the exact tokenizer configuration and corpus
fingerprint, so a checkpoint cannot silently resume with a different tokenizer
or dataset. The original 260-token ByteTokenizer remains the default when
--tokenizer-config is omitted; existing checkpoints are not migrated.

## Recommended corpus review before long training

Build a balanced mix of Arabic and English material across:
- foundational computer science and operating-system concepts;
- network protocols, system administration and defensive operations;
- secure coding, threat modeling and vulnerability explanation;
- clear question/answer and instruction examples for a later supervised stage.

Use a source manifest that records the document title, owner/source URL,
license or written permission, collection date, language, content category,
and the group_id used in JSONL. Keep held-out sets representative and ensure
that near-duplicate passages do not appear across splits. Run human spot checks
and factual verification before trusting any training text.

The model is still a small next-token language model, not yet instruction-tuned,
not yet connected to the desktop chat UI, and not approved for autonomous
security decisions. A low validation loss is not a factuality or safety metric.
