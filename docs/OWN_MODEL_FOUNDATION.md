# AI AYFAM — from-scratch model foundation

## Model baseline

AI AYFAM uses its own decoder-only Transformer initialized from random weights.
It does not load Llama, Qwen, Ollama models, third-party checkpoints, or
pretrained embeddings.

The initial proof-of-concept configuration has 3,042,432 parameters, 8 layers,
6 attention heads, width 192, context length 128, and tied token/output embeddings.
It validates the code and training pipeline; it is not expected to behave like
a mature general-purpose assistant.

## Runtime dependencies

PyTorch stays out of the desktop application's base requirements. The regular
AI AYFAM GUI installation therefore remains lightweight.

For CPU-only training on Linux Mint, activate the project's .venv and install
the optional training dependencies:

~~~bash
python -m pip install --index-url https://download.pytorch.org/whl/cpu -r requirements-training.txt
python -m model_factory.cli profile
~~~

The runtime planner adapts batch size, gradient accumulation, checkpoint
frequency and CPU threads based on available memory. It never silently changes
the model dimensions. A checkpoint carries model/tokenizer configuration and
the corpus fingerprint, so moving between computers does not silently switch
architecture or data.

## Corpus and tokenizer workflow

Prepare a raw UTF-8 JSONL corpus with source and license metadata, then run the
preparation, strict audit and BPE tokenizer commands described in
[CORPUS_AND_BPE.md](CORPUS_AND_BPE.md).

The original deterministic UTF-8 ByteTokenizer remains the default when
--tokenizer-config is omitted. The optional ByteBPETokenizer learns its merge
rules from the train split only. Its versioned merge table is stored in the
checkpoint configuration; a changed tokenizer cannot silently resume an old
checkpoint.
The original deterministic UTF-8 ByteTokenizer remains available and is used
when --tokenizer-config is omitted. The optional ByteBPETokenizer learns its
merge rules from the train split only. Its versioned merge table is stored in
the checkpoint configuration; a changed tokenizer cannot silently resume an
old checkpoint.

## Training

After preparing a corpus and learning a BPE tokenizer:

~~~bash
python -m model_factory.cli train \
  --corpus ~/ayfam-training-data/ayfam-prepared.jsonl \
  --tokenizer-config ~/ayfam-training-data/ayfam-bpe.json \
  --output runs/ayfam-bpe/latest.pt \
  --steps 1000
~~~

Resume using the same prepared corpus and tokenizer:

~~~bash
python -m model_factory.cli train \
  --corpus ~/ayfam-training-data/ayfam-prepared.jsonl \
  --tokenizer-config ~/ayfam-training-data/ayfam-bpe.json \
  --output runs/ayfam-bpe/latest.pt \
  --steps 2000 \
  --resume runs/ayfam-bpe/latest.pt
~~~

Checkpoints contain model and optimizer state, global step, tokenizer and model
configurations, corpus fingerprint, CPU/available CUDA RNG states, and software
and device metadata. Writes are atomic. Loading uses weights_only mode and
refuses architecture, tokenizer, data fingerprint or key optimizer-setting
mismatches. This first version resumes at an epoch boundary with a fresh
deterministic shuffle pass; it does not save an exact mid-epoch data cursor.


## Desktop training workspace

Install the optional CPU training dependencies in the project's virtual
environment, then open AI AYFAM and choose **تدريب نموذج AYFAM** from the
sidebar. Select a corpus that has already passed the strict preparation audit,
choose a short initial step count (the default is 20), and explicitly press
**بدء التدريب المحلي**. Opening the application or this page never starts
training automatically.

The desktop runner learns Byte BPE merges from the train split only, trains
the from-scratch Transformer on CPU, reports optimizer steps/loss/learning
rate/process memory, evaluates on validation data, and writes an atomic
checkpoint. The run folder is local to the machine:

~~~text
~/.local/share/ayfam/training/runs/run-<timestamp>/
  latest.pt
  tokenizer.json
~~~

The stop control requests a graceful stop at an optimizer-step boundary; the
latest checkpoint is saved rather than terminating the process. Training
artifacts and source corpora are not uploaded to GitHub or external services.
The model remains separate from the security chat UI until a later integration
and instruction-tuning phase.

## Local inference and evaluation

Once a training run has produced a checkpoint, export the optimizer-free model
artifact, then use the generation/evaluation/benchmark commands in
[INFERENCE_EVALUATION_BENCHMARK.md](INFERENCE_EVALUATION_BENCHMARK.md).

## Current limits and next steps

- The BPE implementation is a transparent byte-level baseline with whitespace
  pre-tokenization boundaries; it is not claimed to match GPT's full tokenizer
  segmentation or optimized tokenizer throughput.
  segmentation or throughput.
- Language labels are Unicode-script heuristics, not a full language detector.
- Corpus preparation catches selected high-confidence credential patterns and
  exact normalized duplicates. It does not detect every secret, PII item,
  paraphrase, or near-duplicate; human source review remains mandatory.
- Non-empty license/permission metadata is recorded, but software cannot prove
  the legal validity of a supplied license or owner permission.
- Training is causal next-token learning only. The model is not instruction-tuned,
  not connected to the desktop chat UI, and not approved for autonomous
  cybersecurity decisions.
- Text generated by a teacher model may later be considered as supervised data
  only after independent provenance, licensing, quality and factual checks.
  API-generated text without teacher logits is sequence-level data, not ordinary
  logit-level distillation.

A low training loss or a successful build is not evidence that the model is
factual, safe, or ready for operational security decisions.
