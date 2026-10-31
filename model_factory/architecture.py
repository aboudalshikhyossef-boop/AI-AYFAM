"""AI AYFAM's decoder-only Transformer, initialized from random weights only."""

from __future__ import annotations

import math

from model_factory.config import ModelConfig

try:
    import torch
    from torch import nn
    import torch.nn.functional as F
except ImportError:  # Keep the desktop application usable without training extras.
    torch = None
    nn = None
    F = None


if nn is not None:

    class CausalSelfAttention(nn.Module):
        def __init__(self, config: ModelConfig):
            super().__init__()
            self.n_head = config.n_head
            self.head_dim = config.n_embd // config.n_head
            self.qkv = nn.Linear(config.n_embd, 3 * config.n_embd)
            self.proj = nn.Linear(config.n_embd, config.n_embd)
            self.attention_dropout = nn.Dropout(config.dropout)
            self.residual_dropout = nn.Dropout(config.dropout)
            mask = torch.triu(
                torch.ones(config.block_size, config.block_size, dtype=torch.bool),
                diagonal=1,
            )
            self.register_buffer("causal_mask", mask, persistent=False)

        def forward(self, hidden_states):
            batch, length, width = hidden_states.shape
            qkv = self.qkv(hidden_states)
            qkv = qkv.view(batch, length, 3, self.n_head, self.head_dim)
            query, key, value = qkv.permute(2, 0, 3, 1, 4).unbind(0)
            scores = (query @ key.transpose(-2, -1)) * (self.head_dim ** -0.5)
            scores = scores.masked_fill(
                self.causal_mask[:length, :length], torch.finfo(scores.dtype).min
            )
            weights = F.softmax(scores, dim=-1)
            weights = self.attention_dropout(weights)
            attended = weights @ value
            attended = attended.transpose(1, 2).contiguous().view(batch, length, width)
            return self.residual_dropout(self.proj(attended))


    class TransformerBlock(nn.Module):
        def __init__(self, config: ModelConfig):
            super().__init__()
            self.norm_attention = nn.LayerNorm(config.n_embd)
            self.attention = CausalSelfAttention(config)
            self.norm_mlp = nn.LayerNorm(config.n_embd)
            self.mlp = nn.Sequential(
                nn.Linear(config.n_embd, config.ffn_dim),
                nn.GELU(),
                nn.Linear(config.ffn_dim, config.n_embd),
                nn.Dropout(config.dropout),
            )

        def forward(self, hidden_states):
            hidden_states = hidden_states + self.attention(self.norm_attention(hidden_states))
            return hidden_states + self.mlp(self.norm_mlp(hidden_states))


    class AYFAMTransformer(nn.Module):
        """A compact GPT-style language model; no downloaded or imported weights."""

        def __init__(self, config: ModelConfig | None = None):
            super().__init__()
            self.config = config or ModelConfig()
            self.token_embedding = nn.Embedding(self.config.vocab_size, self.config.n_embd)
            self.position_embedding = nn.Embedding(self.config.block_size, self.config.n_embd)
            self.embedding_dropout = nn.Dropout(self.config.dropout)
            self.blocks = nn.ModuleList(
                TransformerBlock(self.config) for _ in range(self.config.n_layer)
            )
            self.final_norm = nn.LayerNorm(self.config.n_embd)
            self.lm_head = nn.Linear(self.config.n_embd, self.config.vocab_size, bias=False)
            if self.config.tie_embeddings:
                self.lm_head.weight = self.token_embedding.weight
            self.apply(self._initialize_weights)

        @staticmethod
        def _initialize_weights(module):
            if isinstance(module, (nn.Linear, nn.Embedding)):
                nn.init.normal_(module.weight, mean=0.0, std=0.02)
                if isinstance(module, nn.Linear) and module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.LayerNorm):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

        def forward(self, input_ids, targets=None):
            if input_ids.ndim != 2:
                raise ValueError("input_ids must have shape [batch, sequence]")
            batch, length = input_ids.shape
            if length == 0 or length > self.config.block_size:
                raise ValueError("sequence length must be within the configured block size")
            if input_ids.dtype != torch.long:
                raise TypeError("input_ids must use torch.long")
            positions = torch.arange(length, device=input_ids.device).unsqueeze(0)
            hidden_states = self.token_embedding(input_ids) + self.position_embedding(positions)
            hidden_states = self.embedding_dropout(hidden_states)
            for block in self.blocks:
                hidden_states = block(hidden_states)
            logits = self.lm_head(self.final_norm(hidden_states))
            loss = None
            if targets is not None:
                if targets.shape != input_ids.shape:
                    raise ValueError("targets must have the same shape as input_ids")
                loss = F.cross_entropy(
                    logits.reshape(batch * length, self.config.vocab_size),
                    targets.reshape(batch * length),
                    ignore_index=self.config.pad_token_id,
                )
            return {"logits": logits, "loss": loss}

        @torch.no_grad()
        def generate(
            self,
            input_ids,
            *,
            max_new_tokens: int = 64,
            temperature: float = 0.8,
            top_k: int | None = 40,
            eos_token_id: int | None = None,
        ):
            if isinstance(max_new_tokens, bool) or not isinstance(max_new_tokens, int) or max_new_tokens < 0:
                raise ValueError("max_new_tokens must be a non-negative integer")
            if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
                raise ValueError("temperature must be a finite non-negative number")
            if not math.isfinite(float(temperature)) or temperature < 0:
                raise ValueError("temperature must be a finite non-negative number")
            if top_k is not None and (isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0):
                raise ValueError("top_k must be a positive integer or None")
            was_training = self.training
            self.eval()
            generated = input_ids
            eos_id = self.config.eos_token_id if eos_token_id is None else eos_token_id
            try:
                for _ in range(max_new_tokens):
                    context = generated[:, -self.config.block_size :]
                    logits = self(context)["logits"][:, -1, :]
                    if temperature == 0:
                        next_token = torch.argmax(logits, dim=-1, keepdim=True)
                    else:
                        logits = logits / temperature
                        if top_k is not None:
                            threshold = torch.topk(logits, min(top_k, logits.size(-1))).values[:, -1, None]
                            logits = logits.masked_fill(logits < threshold, float("-inf"))
                        probabilities = F.softmax(logits, dim=-1)
                        next_token = torch.multinomial(probabilities, num_samples=1)
                    generated = torch.cat((generated, next_token), dim=1)
                    if eos_id is not None and bool(torch.all(next_token == eos_id)):
                        break
            finally:
                self.train(was_training)
            return generated

        def parameter_count(self) -> int:
            return sum(parameter.numel() for parameter in self.parameters())


else:

    class AYFAMTransformer:  # pragma: no cover - exercised only without the optional extra
        def __init__(self, config: ModelConfig | None = None):
            del config
            raise RuntimeError(
                "PyTorch is not installed. Install requirements-training.txt to build or train AYFAM."
            )


def require_torch():
    if torch is None:
        raise RuntimeError(
            "PyTorch is not installed. Install requirements-training.txt to build or train AYFAM."
        )
    return torch
