# AYFAM corpus workspace — phase 1

## Purpose

This phase makes the data path usable from the desktop application. The user
selects a local raw JSONL file, imports a private copy into the AYFAM data
directory, prepares and audits it, and then starts training from the prepared
file. Opening the page never imports data or starts training automatically.

## Committed starter corpus

`data/seed_corpus/v0.1/ayfam-seed-v0.1.jsonl` is a small, project-authored
fixture included to test the complete pipeline and provide realistic examples
for the first UI workflow.

| Property | Value |
|---|---:|
| Records | 60 |
| Arabic records | 42 |
| English records | 18 |
| Train / validation / test | 54 / 3 / 3 |
| Topics | Computing, programming, operating systems, networking, defensive security |
| License label | MIT |
| Provenance | Project-authored starter material |

The language figures count records, not tokens. The small validation and test
sets are smoke-test fixtures, not statistically meaningful evaluation sets.
The texts are short and intentionally repetitive in structure; this corpus is
not large or diverse enough for useful general language-model training. Replace
or extend it with independently reviewed, higher-quality sources before
attempting serious training.

The adjacent `source_manifest.csv` records IDs, group IDs, titles, provenance,
license label, language, topic, split, and collection date. Each record has a
unique group ID so the explicit splits remain isolated.

## Desktop workflow

1. Open **تدريب نموذج AYFAM**.
2. Choose the raw JSONL file. The repository seed file is preselected.
3. Press **استيراد وتجهيز البيانات**.
4. The background worker copies the file to the user's private raw workspace,
   runs Unicode normalization, duplicate and credential-pattern checks,
   creates or validates splits, and writes a prepared file.
5. On success, the prepared file is placed in the training field. The user
   explicitly starts a separate CPU training run.

The local paths are:

~~~text
~/.local/share/ayfam/training/corpora/
  raw/
  prepared/
~/.local/share/ayfam/training/runs/
~~~

Raw imports use SHA-256-derived destination names and owner-only permissions.
The original source file is not modified. The prepared files and checkpoints
are local artifacts and are not uploaded to GitHub.

## External downloads are deliberately not part of phase 1

A future in-app dataset catalog/downloader should be implemented only after
each source has been reviewed for model-training permissions, redistribution
conditions, attribution, collection method, versioning, and removal requests.
Do not treat an accessible web page or a non-empty license string as proof that
all underlying text can legally be used for model training.

## Scope and safety limits

- This workflow accepts JSONL; PDF, HTML, EPUB, and archive ingestion are not
  implemented here.
- Import does not guarantee the corpus is free of personal data, secrets,
  copyrighted text, or inaccurate statements. The selected source must be
  reviewed before import.
- Exact deduplication cannot detect paraphrases or every near-duplicate.
- Language labels are basic script heuristics, not a full language detector.
- The model still requires larger curated pretraining material and a separate
  instruction-tuning dataset before it can behave like an assistant.
