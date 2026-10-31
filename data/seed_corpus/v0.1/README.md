# AYFAM Seed Corpus v0.1

This is a small, project-authored starter corpus committed for development and
end-to-end workflow testing. It is deliberately not presented as a production
pretraining dataset.

- Records: 60
- Arabic records: 42
- English records: 18
- Train / validation / test: 54 / 3 / 3 records
- Topics: computing foundations, programming, operating systems, networking,
  and defensive cybersecurity
- Provenance: original project-authored educational text
- License: MIT, consistent with the repository license
- Collection date: 2026-11-01

Each record is an independent short document with a unique `group_id`. The
explicit split labels are provided for reproducible smoke tests. They are not
large enough to support reliable model-quality conclusions. The sample should
be replaced or supplemented with larger, independently reviewed and
license-cleared sources before meaningful training.

The corpus intentionally contains no credentials, customer data, host
inventories, scan results, or personal records. The source manifest is stored
beside the JSONL file.
