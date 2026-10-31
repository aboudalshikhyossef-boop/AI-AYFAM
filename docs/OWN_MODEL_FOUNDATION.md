# AI AYFAM — from-scratch model foundation

## What this milestone creates

This is the first real neural-model foundation in AI AYFAM. It does **not** load
Llama, Qwen, Ollama models, third-party checkpoints, or pretrained embeddings.
\`AYFAMTransformer\` initializes every parameter randomly and learns only from
the explicitly supplied local corpus.

The first proof-of-concept configuration is a decoder-only Transformer with
UTF-8 byte tokens, 8 layers, 6 attention heads, width 192, context length 128,
and tied token/output embeddings. Its expected parameter count is **3,042,432**
(about 12.2 MB for float32 weights, excluding optimizer state and activations).
This size validates the end-to-end pipeline; it is not expected to behave like
a mature general-purpose assistant.

## Keep the desktop install lightweight

PyTorch is intentionally **not** in \`requirements.txt\`. The normal GUI install
therefore does not download a large machine-learning runtime.

For CPU-only training on Linux Mint, activate the project's \`.venv\`, then run:

\`\`\`bash
python -m pip install --index-url https://download.pytorch.org/whl/cpu -r requirements-training.txt
python -m model_factory.cli profile
\`\`\`

No CUDA toolkit or discrete GPU is needed for the first CPU proof-of-concept.
The runtime profiler limits threads and micro-batches conservatively based on
available memory and CPU count. It adapts execution settings, **not** model
dimensions, so a checkpoint can move between computers without silently
changing its architecture.

## Corpus format and provenance

Training data is newline-delimited JSON (UTF-8), one object per line:

\`\`\`json
{"id":"ar-001","text":"نص عربي كتبه مالك المشروع.","source":"project-authored","license":"owner-authorized","split":"train"}
{"id":"ar-002","text":"نص مستقل للتقييم.","source":"project-authored","license":"owner-authorized","split":"validation"}
\`\`\`

Every record must include:
- \`text\`: non-empty training text.
- \`source\`: where the text came from (for example, a document identifier).
- \`license\`: an SPDX license identifier or a documented owner-permission label.
- \`split\`: exactly \`train\`, \`validation\`, or \`test\`.

Do not put secrets, private user data, live credentials, or security-sensitive
machine inventories into the corpus. Do not scrape or ingest third-party text
without confirming its license and redistribution/training permissions. For
project-owned text that is not released under an open license, use a clear
owner-permission label and keep that permission record with the source metadata.
Keep validation/test records separate from training examples. The loader streams
records with a bounded line read, rejects malformed JSON, invalid UTF-8, missing
provenance, unknown splits, and oversized lines. Training uses a deterministic
bounded shuffle buffer (seeded per pass), so it never needs to hold the corpus
in RAM. The corpus is fingerprinted so resume refuses a different data file by default.

Validate a dataset before training:

\`\`\`bash
python -m model_factory.cli validate-corpus ~/ayfam-training-data/ayfam.jsonl
\`\`\`

## First training run

\`\`\`bash
python -m model_factory.cli train \\
  --corpus ~/ayfam-training-data/ayfam.jsonl \\
  --output runs/ayfam-3m/latest.pt \\
  --steps 1000
\`\`\`

Resume with the same corpus and checkpoint:

\`\`\`bash
python -m model_factory.cli train \\
  --corpus ~/ayfam-training-data/ayfam.jsonl \\
  --output runs/ayfam-3m/latest.pt \\
  --steps 2000 \\
  --resume runs/ayfam-3m/latest.pt
\`\`\`

The checkpoint stores model and optimizer state, step count, architecture and
tokenizer configurations, corpus fingerprint, CPU and available CUDA RNG states,
and software/device metadata. Writes are atomic. Loading uses PyTorch's
\`weights_only=True\` mode and rejects schema, architecture, tokenizer, data, and
key optimizer-setting mismatches. Treat checkpoints as valuable project artifacts
and keep backups before moving or replacing them. A resumed run restores
model/optimizer/RNG/step state and starts a fresh bounded shuffle pass over the
same fingerprinted corpus; this first version does not serialize an exact
mid-epoch data-loader cursor.

## Current boundaries and next milestones

- The byte tokenizer is deterministic and dependency-free. A learned
  Arabic/English BPE tokenizer is a later, versioned migration; tokenizer
  changes must never be silently applied to an existing checkpoint.
- The initial CLI performs causal next-token training on local text. It is not
  yet instruction-tuned, tool-enabled, or connected to the desktop chat UI.
- Text produced by a teacher model can later be used as supervised examples
  only after provenance, licensing, quality, and factual checks. This is
  sequence-level data distillation, not logit distillation.
- Next stages: curate a balanced Arabic/English cybersecurity corpus, add
  held-out quality and memorization checks, improve tokenizer efficiency,
  benchmark CPU memory/time on the actual Linux Mint laptop, and only then
  consider instruction tuning and desktop inference integration.

Never treat a small training loss or a successful build as evidence that the
model is secure, factual, or ready for operational cybersecurity decisions.
