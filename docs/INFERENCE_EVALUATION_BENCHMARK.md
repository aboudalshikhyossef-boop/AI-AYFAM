# AI AYFAM — local inference, evaluation and benchmarking

This guide covers the first model-only runtime. It does not download pretrained
weights or use an external AI provider. The local model must first be trained
from a project-authorized corpus.

## 1. Install the optional CPU training/runtime dependencies

After pulling the merged changes into your Linux Mint checkout, activate the
project virtual environment and install the optional CPU-only PyTorch package:

~~~bash
source .venv/bin/activate
python -m pip install --index-url https://download.pytorch.org/whl/cpu -r requirements-training.txt
~~~

The regular desktop dependencies remain separate from PyTorch.

## 2. Export a lightweight model artifact

Training checkpoints also contain optimizer state, RNG state and training
metadata. Inference does not need the optimizer. Export a compact model-only
artifact after training:

~~~bash
python -m model_factory.cli export-model \
  --checkpoint runs/ayfam-bpe/latest.pt \
  --output runs/ayfam-bpe/inference.pt
~~~

The export contains:
- the model configuration and model weights;
- the exact versioned tokenizer configuration;
- the source training step and prepared-corpus fingerprint;
- export/runtime metadata.

It deliberately omits optimizer state. Export and load use PyTorch's
\`weights_only=True\` mode. The artifact is written atomically. Keep the original
training checkpoint if you intend to resume training; the exported artifact is
for inference/evaluation only.

For a ByteTokenizer checkpoint, the same command works. The exact tokenizer
configuration is validated during export and load.

## 3. Generate a local continuation

~~~bash
python -m model_factory.cli generate \
  --model runs/ayfam-bpe/inference.pt \
  --prompt "اشرح مفهوم الجدار الناري في الشبكات" \
  --max-new-tokens 64 \
  --temperature 0.8 \
  --top-k 40 \
  --top-p 0.9 \
  --seed 42
~~~

Sampling settings:
- temperature 0 selects greedy decoding; higher values increase randomness.
- top-k limits the candidate set to the highest-scoring K tokens. Set it to 0
  to disable top-k filtering.
- top-p applies nucleus sampling after top-k. Set it to 1.0 to disable it.
- seed makes sampling repeatable for a fixed model, prompt and software/runtime.

Generation stops at the tokenizer's EOS token or at max-new-tokens. PAD, BOS
and UNK are suppressed from free-form output. Long prompts are truncated to the
model's configured context window. The generated text is a continuation, not a
guarantee of correctness; the initial model is not yet instruction-tuned.

## 4. Evaluate on held-out data

Evaluate the test split:

~~~bash
python -m model_factory.cli evaluate \
  --model runs/ayfam-bpe/inference.pt \
  --corpus ~/ayfam-training-data/ayfam-prepared.jsonl \
  --split test \
  --batch-size 1
~~~

For iteration during development, evaluate validation separately:

~~~bash
python -m model_factory.cli evaluate \
  --model runs/ayfam-bpe/inference.pt \
  --corpus ~/ayfam-training-data/ayfam-prepared.jsonl \
  --split validation
~~~

Evaluation reports token-weighted cross-entropy loss, perplexity, next-token
accuracy, token/batch counts and the corpus fingerprint. Unlike averaging
batch means, the loss is weighted by the number of non-PAD target tokens.

The evaluation corpus must pass the strict prepared-corpus audit and its
SHA-256 fingerprint must exactly match the training corpus recorded in the
artifact. This prevents accidentally evaluating against a changed or unrelated
dataset. Keep the test split untouched during model/tokenizer/optimizer tuning;
use validation for iterative decisions.

Perplexity and next-token accuracy are language-model diagnostics, not measures
of factuality, helpfulness, cybersecurity skill, privacy or safety. Always
combine them with human-reviewed prompts and held-out task-specific evaluations.

## 5. Benchmark the actual Linux Mint laptop

Run a conservative default benchmark:

~~~bash
python -m model_factory.cli benchmark \
  --model runs/ayfam-bpe/inference.pt \
  --device cpu \
  --batch-size 1 \
  --threads 1 \
  --warmup 2 \
  --iterations 10 \
  --generation-tokens 16
~~~

The report includes:
- forward-pass tokens/second for the requested batch and context length;
- greedy autoregressive generation tokens/second;
- peak process RSS in MiB;
- peak allocated CUDA memory when CUDA is selected;
- model size, device, PyTorch version, thread count and timing inputs.

The benchmark does not train the model or change its weights. Run it once with
one thread and again with two threads if the laptop remains responsive. Close
other heavy applications and compare repeated runs; thermal throttling, memory
pressure and desktop activity affect measurements. The peak RSS value includes
the Python/PyTorch process and loaded model, not just model weights.

To compare context lengths while holding all other settings fixed, use for
example \`--sequence-length 64\` and \`--sequence-length 128\`. The selected length
cannot exceed the model's context window. Do not increase batch size or threads
aggressively on an 8 GB laptop.

## 6. Suggested first device-side report

After syncing the merged code and exporting a real trained checkpoint, run the
benchmark command and save its JSON output in a private local experiment folder.
Share the JSON report only after checking it contains no private paths or
machine identifiers. Do not upload model checkpoints or private corpus files
to the repository.

The next training decision should use measured tokens/second and RAM usage on
the actual machine, together with validation loss and reviewed generation
samples. Do not scale model dimensions or launch long training runs based only
on a green CI build.
