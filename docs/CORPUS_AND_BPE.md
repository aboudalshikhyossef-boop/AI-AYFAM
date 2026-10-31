# AI AYFAM — corpus preparation and Arabic/English BPE

This guide covers the reproducible path from raw, authorized text to a
validated training corpus and a tokenizer learned only from the training split.
The desktop workflow can import a selected local JSONL file, preserve a private
copy, prepare it, and then send the prepared corpus to local training. It does
not automatically download Internet datasets in this phase.

## 1. Raw input format

Each line is one UTF-8 JSON object representing a document or document segment:

~~~json
{"id":"doc-ar-001","group_id":"source-ar-001","text":"نص عربي موثق ومصرح باستخدامه في التدريب.","source":"owner-or-project:document-id","license":"MIT"}
{"id":"doc-en-001","group_id":"source-en-001","text":"An independently authored English sample.","source":"owner-or-project:document-id","license":"CC-BY-4.0"}
~~~

Required fields:
- `text`: non-empty text.
- `source`: provenance, such as a project-authored identifier or the original URL.
- `license`: an SPDX license identifier or a documented permission label.

Recommended fields:
- `id`: stable record identifier.
- `group_id`: stable ID for the original document or source group. All chunks
  from one document must share the same value.
- `split`: optional `train`, `validation`, or `test`. Either provide it on
  every row or omit it on every row so the preparation tool can assign splits.

Use a distinct `group_id` for each independent document. Never split chunks
from one original document across train, validation, and test. If `group_id`
is omitted, the source value becomes the grouping key; do not use one generic
source value for unrelated documents.

Keep full private or third-party corpora outside the Git repository. The
repository includes only a small project-authored seed fixture for exercising
the import and training workflow. See [CORPUS_WORKSPACE.md](CORPUS_WORKSPACE.md)
for the seed manifest and its limitations.

Do not include API keys, passwords, private keys, personal records, customer
data, host inventories, private scan results, or information the owner has not
authorized for model training. A non-empty license label is provenance
metadata; the software cannot prove that the stated permission is valid.
Review source terms and the actual content before import.

## 2. Import and prepare from the desktop application

Install the optional CPU training dependencies described in
[OWN_MODEL_FOUNDATION.md](OWN_MODEL_FOUNDATION.md), open AI AYFAM, and select
**تدريب نموذج AYFAM**.

1. Choose a raw JSONL file. The committed seed corpus is preselected as a
   workflow example.
2. Press **استيراد وتجهيز البيانات**. AYFAM copies the original file to the
   per-user raw workspace, then normalizes, deduplicates, splits, and audits it
   in a background worker.
3. After successful validation, the prepared JSONL path appears in the
   training field. Choose a short step count and explicitly press
   **بدء التدريب المحلي**.

The imported raw copy and prepared file stay under:

~~~text
~/.local/share/ayfam/training/corpora/
  raw/
  prepared/
~~~

The import keeps the original file unchanged, uses an SHA-256-derived filename
to avoid silently overwriting a different corpus, and stores the private copy
with owner-only file permissions. Training checkpoints remain in the separate
`runs/` directory under the same local AYFAM data root.

The current desktop phase imports local JSONL files; it does not fetch external
datasets or decide whether a remote website permits model training. A future
source downloader must have a reviewed source catalog, per-source license and
attribution handling, versioned collection records, and clear user consent.

## 3. Prepare and split from the command line (optional)

The GUI is the preferred path for normal use. For reproducible development
workflows, the same preparation engine is available from the terminal:

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

If source rows contain explicit split labels, include them on every row.
Conflicting split assignments for one source group are rejected. Otherwise,
the tool assigns a deterministic split by `group_id` and seed, not by row.

Preparation writes atomically and:
- normalizes Unicode to NFC and standardizes line endings and spacing;
- preserves Arabic joining controls while dropping other control/format chars;
- rejects selected high-confidence credential patterns;
- removes exact duplicates after normalization using a disk-backed SQLite index;
- rejects identical normalized text appearing in different splits;
- rejects a source group assigned to multiple splits;
- records a script-based language summary and a SHA-256 corpus fingerprint.

Exact deduplication does not detect paraphrases or all near-duplicates.
Language classification is a Unicode-script heuristic, not full language
identification. Credential scanning catches selected patterns only and cannot
guarantee that no secrets or personal information remain. Human review is
mandatory.

Audit the prepared corpus:

~~~bash
python -m model_factory.cli audit-prepared-corpus \
  ~/ayfam-training-data/ayfam-prepared.jsonl
~~~

## 4. Learn BPE from train only

~~~bash
python -m model_factory.cli train-tokenizer \
  --corpus ~/ayfam-training-data/ayfam-prepared.jsonl \
  --output ~/ayfam-training-data/ayfam-bpe.json \
  --vocab-size 1024 \
  --min-frequency 2
~~~

The tokenizer starts from 256 UTF-8 byte IDs and the four special IDs used by
the original byte tokenizer. It learns merge rules from records marked
`train` only; validation and test text are never used to learn the vocabulary.
Whitespace is preserved and used as a pre-tokenization boundary. This is a
transparent byte-BPE baseline, not a claim of matching GPT's full
pre-tokenization or optimized throughput.

The tokenizer configuration stores a schema version, vocabulary size, special
token IDs, and ordered merge table. Keep it with its checkpoint. Do not retrain
or edit the merge table when resuming an existing checkpoint.

## 5. Train with the learned tokenizer

~~~bash
python -m model_factory.cli train \
  --corpus ~/ayfam-training-data/ayfam-prepared.jsonl \
  --tokenizer-config ~/ayfam-training-data/ayfam-bpe.json \
  --output runs/ayfam-bpe/latest.pt \
  --steps 1000
~~~

The model vocabulary size is derived from the selected tokenizer. Checkpoint
loading verifies tokenizer configuration and corpus fingerprint so a run
cannot silently resume against different data or token IDs.

## 6. Dataset quality before serious training

Build a source manifest that records document title, owner or source URL,
license or written permission, collection date, language, category, version,
and the `group_id` used in JSONL.

Review the dataset for:
- useful Arabic and English content measured by token count, not only document count;
- balanced coverage of foundational computing, programming, operating systems,
  networking, defensive security, and later instruction examples;
- source quality, factual accuracy, and clear provenance;
- exact duplicates and near-duplicates across all splits;
- sensitive data, personal information, and material outside the permitted scope.

Keep the test split untouched during model development. Use validation for
iteration and human-reviewed task evaluations for factuality, usefulness, and
safety. Perplexity and next-token accuracy do not measure those qualities.

The model remains a small causal next-token language model. It is not
instruction-tuned, not a general-purpose assistant, and not approved for
autonomous cybersecurity decisions.
