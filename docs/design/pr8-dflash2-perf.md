# PR8 - DFlash2 speculative decoding: acceptance, not draft cost

Status: design, not implemented.
Verified against fork commit `09ac6322b` (2026-09-13). Every code anchor was re-read at that commit.

This is a **performance track**, separate from the auth work (PR1-PR7). It shares the repo, the
agent workflow and features.json, and nothing else. No feature here touches auth code, and no
feature here is `security_sensitive`.

> **Retraction notice.** An earlier revision of this document was built on a "~47.5 ms draft step
> against an ~18 ms bandwidth expectation, a 2.6x unexplained excess" premise. **That premise was
> wrong and is fully retracted.** It came from subtracting a no-speculation target forward time from
> the speculative step time, which is not the verify-step cost, and it did not account for a 1.043 GB
> shared lm_head read. The measured draft cost is ~23 ms and is exactly bandwidth-explained. Every
> conclusion that rested on the excess has been removed rather than rewritten. See sections 3 and 5.

## 1. Scope

Target deployment: GX10 (`llama.kscsc.local`, 192.168.95.201), NVIDIA GB10 Grace Blackwell,
aarch64, 121 GB unified LPDDR5X, CUDA 13 / driver 580, `CMAKE_CUDA_ARCHITECTURES=121a-real`.
Memory bandwidth is the binding constraint: ~273 GB/s peak, ~213 GB/s effective.

Workload: `llama-server` `Coder` preset, target Qwen3.8-27B UD-Q4_K_M (16.46 GB) with a DFlash2
draft `Qwen3.8-27B-DFlash2-BF16.gguf` (3.86 GB, ~1.93 B params BF16). Draft metadata:
`block_size=8` (so `--spec-draft-n-max` clamps to 7), `n_extract=5`, `sample_from_anchor=true`,
vocab ~248k (`mask_token_id=248070`). Server: 6 slots x 98304 ctx, `kv-unified: false`, `p_min=0`.

**The track is about acceptance rate.** Mean accepted length falls from 4.6 at ctx 8192 to 3.15 at
production context, and that single factor explains nearly all of the 43 -> 25 t/s drop. Draft-side
compute is measured, understood, and not worth attacking (section 5).

Non-goals: changing the target model, the quantization, or anything in the verification path's
sampling semantics. No new ggml ops. No retraining or re-export of the draft checkpoint.

## 2. Anchor verification

| Reference | Actual at 09ac6322b | Note |
|---|---|---|
| `build_dflash2_selector()` | `src/models/dflash.cpp:475-565` | brief said 473-565 |
| draft lm_head fallback to `ctx_other` | `src/models/dflash.cpp:772-781` | |
| `res->t_logits` assignment | `src/models/dflash.cpp:812`, selector call at `:824` | brief said ~785 |
| `ggml_top_k` over full logits | `src/models/dflash.cpp:496` | |
| `ggml_pad(row, n_embd - row_used, ...)` | `src/models/dflash.cpp:539` | brief said ~541 |
| redundant `ggml_repeat` | `src/models/dflash.cpp:528` and `:534` | |
| `d2t` reduced-vocab scatter path | `src/models/dflash.cpp:798-811` | |
| lattice walk | `common/speculative.cpp:1236-1263` | brief said ~1236-1256; the `n_min` clear at `:1260-1262` is inside the block |
| batch built with `logits=false` | `common/speculative.cpp:1208` | |
| unused per-seq sampler | `common/speculative.cpp:1232`, reset at `:1198` | |
| draft ctx sized to target ctx | `common/speculative.cpp:2549` | |
| `common_speculative_print_stats` | `common/speculative.cpp:2953-2997` | |
| acceptance loop | `common/sampling.cpp:678-706` | |
| `acc per pos` | `tools/server/server-context.cpp:680` | |

## 3. Measured cost model (this is the design's foundation)

All figures below are **measured**, not derived. Draft cost comes from the trace-level `dur(b,g,a)`
counters, which are cumulative totals divided by the draft call count.

> **Two caveats that apply to every number in this section and must travel with them wherever they
> are quoted.**
>
> **Sampling settings.** Everything here was measured at **production sampling**:
> `temperature 1.0, top_p 0.95, top_k 20`. **Nothing here was measured at `--temp 0`.** This matters
> because acceptance is regime-dependent: under greedy target sampling the draft only has to match
> one fixed argmax token, while under a stochastic draw it has to match the actual sample. A
> reproduction run at `--temp 0` will **not** reproduce these numbers, and must not be treated as a
> failure to reproduce. Section 10 splits the protocol accordingly.
>
> **Slot count.** Every figure is **single-slot**. The deployment runs 6 slots. The marginal verify
> cost in particular (~0.79 ms/token) is a single-slot figure, and multi-slot batch aggregation is
> the most plausible way for it to change. Conclusions drawn from it (section 9) inherit the caveat.

Draft step cost:

| Config | total ms / calls | ms per draft |
|---|---|---|
| n_max=3, ctx 8192 | 5658.870 / 257, 8269.991 / 378 | 22.02, 21.88 |
| n_max=5, ctx 8192 | 4337.907 / 191, 6901.611 / 307 | 22.71, 22.48 |
| n_max=7, ctx 8192 | 4066.470 / 176, 5926.596 / 259 | 23.10, 22.88 |
| n_max=7, long ctx | 2983.590 / 127, 5817.023 / 253 | 23.49, 22.99 |

The draft step is **~22-23 ms, flat in `n_max`** (21.9 at n=3 against 23.0 at n=7) **and flat in
context length**.

Why it is exactly that, confirmed by direct GGUF header inspection (pure-python header parse, no
numpy on the box):

* the draft GGUF has 81 tensors and contains **no `output.weight` and no `token_embd.weight`**. It
  does contain `selector_hidden.weight` (5120, 256), `selector_predecessor.weight` (256, 248320) and
  `selector_successor.weight` (256, 248320), all BF16.
* it therefore falls through to the target's lm_head via `cparams.ctx_other`
  (`src/models/dflash.cpp:772-781`).
* the target's `output.weight` (5120, 248320) is Q6_K = **1.043 GB**. (`token_embd.weight` is Q4_K,
  0.715 GB, and is read by `get_rows` only, so it does not contribute a full-tensor read.)

```
per draft step = 3.86 GB draft weights + 1.043 GB shared Q6_K lm_head = 4.90 GB
4.90 GB / 213 GB/s = 23.0 ms        measured: 22.0 - 23.5 ms
```

**There is no unexplained overhead in the draft step.** Stated precisely, because the distinction
decides what may be concluded: this is a **bound on the sum of all non-bandwidth costs**, not an
isolated per-kernel measurement. The bandwidth model accounts for the whole step to within
measurement error, so the selector, the top-k over 248k, the repeat / concat / cast materialization
and the pad-to-`n_embd` **together** fit inside that error bar. No individual one of them was timed
on its own. The conclusion is robust anyway: attributing the entire residual to the top-k alone still
leaves it far below the 3 ms that would have justified acting on it.

Full step decomposition:

| Regime | t/s | mean acc len | step | draft | target verify | draft share |
|---|---|---|---|---|---|---|
| ctx 8192, n_max=7 | 43.2 | 4.6 | 106 ms | 23 ms | 83 ms | 22% |
| long ctx, n_max=7 | 25.05 | 3.15 | 126 ms | 23 ms | 103 ms | 18% |
| no-spec, short | 12.96 | - | 77.5 ms/token | - | 77.5 ms | - |
| no-spec, long | 12.43 | - | 80.5 ms/token | - | 80.5 ms | - |

**The target verify dominates at 78-82% of every step.**

**Key derived number for the whole design:** verifying 8 tokens costs 83 ms where verifying 1 costs
77.5 ms, so the **marginal cost of an extra draft token at verify time is ~0.79 ms**, against a
~23 ms fixed draft cost and an ~80 ms fixed target cost. Extra draft **width is nearly free on this
hardware.** Everything in sections 6 and 7 follows from that one number.

`n_max` sweep, short ctx, mean decode t/s: n=3 -> 29.26, n=5 -> 34.35, n=7 -> 40.19. Monotonic in
width, so `n_max=7` is already optimal and is capped only by the checkpoint's `block_size=8`. The
production setting is correct; this is a **validated finding, not a tuning opportunity**.

Per-position acceptance, `n_max=7` - **this is the curve the track is trying to move**:

| Regime | pos 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|
| ctx 8192 | 0.830 | 0.676 | 0.580 | 0.472 | 0.409 | 0.324 | 0.239 |
| long ctx | 0.638 | 0.504 | 0.323 | 0.236 | 0.189 | 0.142 | 0.110 |

Two things to read off it: the decay with position is steep, which is the regime where a better path
choice pays (section 6); and the whole curve shifts down with context, including position 1, which is
its own problem (section 8).

## 4. Correctness invariant (load-bearing for everything below)

`common_sampler_sample_and_accept_n` (`common/sampling.cpp:678-706`):

```cpp
    for (; i < draft.size(); i++) {
        const llama_token id = common_sampler_sample(gsmpl, ctx, idxs[i], grammar_first);
        common_sampler_accept(gsmpl, id, true);
        result.push_back(id);
        if (draft[i] != id) {
            break;
        }
    }
```

Every emitted token is the **target's** sample. The draft token is only ever compared for equality;
it is never emitted. Therefore any change confined to draft-token selection:

* cannot change the output distribution,
* cannot produce a token the target would not have produced,
* can only change **acceptance rate**, i.e. throughput.

With `temp > 0` the RNG stream advances a different number of times when the accepted length changes,
so a particular realization differs; the distribution does not. With greedy target sampling the
output is bit-identical regardless of the draft.

Consequences for this track:

* the blast radius of a draft-side bug is a throughput regression, which the existing acceptance
  instrumentation (section 10) makes directly visible;
* perplexity or benchmark-suite regression testing is **not** required and would measure noise;
* the one genuine hazard is an **invalid token id** reaching `llama_decode`. `llama_batch_allocr`
  validates ids (`src/llama-batch.cpp:51-52`) and returns an error, so the failure mode is a failed
  decode and an errored request, not memory corruption. The walk consumer still gains a cheap range
  check so the failure degrades to "draft truncated" (section 9).

This invariant is what makes it reasonable to ship draft-side changes on measurement alone.

## 5. Draft-side cost: CLOSED

### 5.1 What was closed and why

| Item | Verdict | Reason |
|---|---|---|
| full-vocab logits for the selector | **won't-do** | the whole draft step is accounted for by weight reads; the projection's marginal cost is inside measurement error |
| `ggml_top_k` over 248064 x 8 | **won't-do** | same. Its cost is bounded below the whole step's measurement error, not measured in isolation (section 3). Secondary reason: `ggml_cuda_op_top_k` asserts `ggml_is_contiguous(src0)`, so restricting the rows forces a `ggml_cont` of ~6.9 MB, making the change **directionally likely** to be a net loss even at a non-zero top-k cost |
| pad-to-`n_embd` at `:539` | **won't-do** | required by the transport, and free. See 5.2 |
| shared Q6_K lm_head read | **won't-do, ceiling recorded** | see 5.3 |
| two redundant `ggml_repeat` at `:528`, `:534` | **won't-do standalone** | real but worth zero measurable throughput, inside a function with three recent upstream commits. See 5.4 |
| unused per-seq CPU sampler for DFlash2 | **do, as a tidy-up** | see 5.4 |

### 5.2 The `ggml_pad` to `n_embd` is required and free

`ggml_pad(ctx0, row, n_embd - row_used, 0, 0, 0)` (`:539`) pads each lattice row from
`row_used = top_k + top_k*top_k` floats out to `n_embd`. It is **required**, because the transport is
`res->t_h_nextn` and `llama_context` copies that buffer out with a hardwired `hparams.n_embd_out()`
row stride:

* `src/llama-context.cpp:1955-1968` - `n_rows * n_embd` bytes
* `src/llama-context.cpp:2074-2078` - `embd_nextn.size = n_embd_out * n_batch` in `output_reserve`
* `src/llama-context.cpp:955-980` - `get_embeddings_nextn_ith` indexes at `i * n_embd`

Removing it means changing that contract for every nextn consumer (MTP, DSpark confidence, DFlash2),
a large edit in a hot upstream file. And it costs `(n_embd - row_used) * block_size * n_blocks * 4`
bytes: under 1 MB per draft step, roughly 5 microseconds at 213 GB/s, against a 23 ms step. Recorded
here so it is not re-proposed.

### 5.3 The shared lm_head: ceiling recorded, out of scope

The Q6_K lm_head is 1.043 of the 4.90 GB read per draft step: **21% of the draft step, but only ~4%
of a full speculative step** (1.043 GB / 213 GB/s = 4.9 ms against a 106-126 ms step).

The only way to cut it is a **reduced-vocabulary draft export** through the existing `model.d2t`
scatter path (`src/models/dflash.cpp:798-811`), which the code already supports. That requires
re-exporting or retraining the checkpoint and is out of scope for this track.

**Ceiling: ~4% throughput, for a checkpoint re-export.** Recorded so nobody relitigates it. If the
draft is ever re-exported for another reason, a reduced draft vocabulary is worth folding in at that
point, not before.

### 5.4 Tidy-ups: one kept, one cut

**Kept (P807).** `common/speculative.cpp` allocates one `common_sampler` per sequence in the DFlash
constructor (`:1021-1027`), calls `common_sampler_reset` on it every draft call (`:1198`), and binds
it at `:1232` - and the DFlash2 branch never uses it (verified: zero references to `smpl` in
`:1236-1263`). `common_sampler_init` resizes its candidate array to `n_vocab`
(`common/sampling.cpp:155`), so at vocab 248320 that is roughly 2 MB per sequence, 12 MB across 6
slots, plus a pointless reset per draft call. Skip the allocation and the reset when `is_dflash2`.
This is a **correctness-neutral cleanup worth approximately zero measurable throughput**, justified
by not allocating 12 MB nobody reads. Its acceptance criteria must not promise a throughput delta. It
touches a constructor, not the churning selector graph.

**Cut.** `ggml_mul_impl` and `ggml_add_impl` in `ggml/src/ggml.c` both assert only
`GGML_ASSERT(ggml_can_repeat(b, a))`, so both ops already broadcast `src1` into `src0`, which makes
the explicit repeats at `src/models/dflash.cpp:528` and `:534` redundant materializations. The
observation is correct and the change would be two lines. It is **cut anyway**: it buys zero
measurable throughput (section 3 bounds the whole selector below measurement error) while editing a
function with three recent upstream commits (`662a0b012`, `cc231cb0d`, `b10f9ca58`). Taking a
permanent rebase conflict in an actively-developed upstream function for an unmeasurable gain is a
bad trade. **If some future PR touches `build_dflash2_selector` for another reason, fold it in
there** - the conflict is already being paid at that point. Recorded here so the observation is not
lost, and so it is not re-proposed as standalone work.

Note the `ggml_repeat_4d` at `:531` is **not** redundant in any case: when `n_pred == 1` the score
genuinely has to be expanded to `top_k` predecessor rows before the concat.

## 6. Lead B (PRIMARY) - exact DP over the lattice instead of greedy

### 6.1 Why this is the primary item

It attacks acceptance directly at **zero GPU cost**: a few microseconds of CPU against a 23 ms GPU
draft step (measured at 4.9 microseconds, section 6.5). The per-position curves in section 3 decay
steeply, which is exactly the regime where committing to a locally-best first step can cost more than
it gains.

**What "exact" means here, and what it does not.** The DP is the exact maximizer of `E[L]` **within
the B-1..B-3 model of section 6.3**. It is not a guarantee of beating greedy on hardware. If the
model's estimate of `p_i` is mis-calibrated in a way that varies across positions, the DP will
faithfully maximize the wrong quantity. That is why the feature ships behind a flag and is judged by
P805's measured per-position curve rather than by the proof.

### 6.2 What the consumer does today

`common/speculative.cpp:1236-1263`:

```
predecessor = 0
for i in 1 .. n_block_tokens-1:
    row     = lattice + (beg + i) * n_embd_dec
    scores  = row + top_k + predecessor*top_k
    predecessor = argmax(scores[0..top_k-1])
    if p_min > 0 and softmax(scores)[predecessor] < p_min: break
    result.push_back((llama_token) row[predecessor])
if result.size() < n_min: result.clear()
```

A pure greedy argmax over a first-order lattice. It maximizes each step's local score and nothing
else.

Row layout, as packed by `build_dflash2_selector`:

```
row[0 .. top_k-1]                 candidate token ids at this block position, F32-cast
row[top_k + p*top_k + c]          score(predecessor candidate p -> candidate c),
                                  with the unary logit of c already added
row[top_k + top_k*top_k .. ]      zero padding out to n_embd
```

Block position 0's row is all zeros and is never read.

### 6.3 Probability model and its assumptions

**B-1**: the per-position acceptance probability of candidate `c` given predecessor `p` is
approximated by the softmax over the `top_k` transition scores:

```
p_i(c | p) = exp(s_i(p,c)) / sum_{c'=0..top_k-1} exp(s_i(p,c'))
```

This is **not a new assumption**. The existing `p_min` early-exit at `:1247-1254` already computes
exactly this quantity (`1 / sum(exp(s_k - s_max))` is the softmax at the argmax) and already treats
it as "the probability". The DP reuses the same estimator and introduces no new modelling error
relative to today's code.

**B-2**: mass outside the `top_k` candidates is unmodelled (treated as zero). The softmax is
normalized over the truncated support, so `p_i` **over-estimates** the true acceptance probability.
The bias is common to all paths through that position, so it distorts the absolute value of `E[L]`
much more than the ranking of paths, and the DP only needs the ranking.

**B-3**: given the chosen path, acceptance events at successive positions are conditionally
independent, so the probability that the first `i` drafted tokens are all accepted is
`prod_{j=1..i} p_j`.

All three go in the new file's header comment, not only here.

### 6.4 The objective, and why neither greedy nor Viterbi is it

The target accepts a **prefix**: if the first mismatch is at position `i+1`, exactly `i` draft tokens
are accepted. So the quantity to maximize is the expected accepted prefix length:

```
E[L] = sum_{i=1..B-1} prod_{j=1..i} p_j          B = n_block_tokens
```

* **Greedy** maximizes `p_i` at each step independently. It ignores that a slightly weaker choice at
  position `i` can open a much stronger continuation.
* **Viterbi** maximizes `prod_{j=1..B-1} p_j`, the probability the **whole** block is accepted. Wrong
  target: a 2% chance of 7 tokens is worse than a 90% chance of 4.
* `E[L]` is the throughput-relevant quantity and is neither.

### 6.5 The DP recurrence

`V_i(p)` = maximum achievable expected accepted tokens from position `i` onward, given candidate
index `p` was chosen at position `i-1`:

```
V_B(p) = 0                                            for all p
V_i(p) = max over c in [0, top_k) of
             p_i(c | p) * (1 + V_{i+1}(c))            for i = B-1 down to 1
```

Derivation: the tail contribution from position `i` is

```
sum_{m>=i} prod_{j=i..m} p_j = p_i * ( 1 + sum_{m>=i+1} prod_{j=i+1..m} p_j ) = p_i * ( 1 + tail_{i+1} )
```

`p_i(c|p)` depends only on `(p, c)` and `tail_{i+1}` only on `c`, so the maximization factorizes and
the recurrence is **exact**: it returns the true maximizer of `E[L]` over all `top_k^(B-1)` paths.

Forward reconstruction, anchor treated as predecessor index 0:

```
c_1 = argmax_c p_1(c | 0)       * (1 + V_2(c))
c_i = argmax_c p_i(c | c_{i-1}) * (1 + V_{i+1}(c))    for i = 2 .. B-1
```

Cost. **An earlier revision of this document stated the exponential count as `B * top_k`. That was
wrong** and is corrected here; the error made one of P803's acceptance criteria unsatisfiable by any
correct implementation.

`p_i(c|p)` is a softmax over the `top_k` transition scores **from predecessor `p`**, so there is a
separate softmax per **(position, predecessor)** pair, not one per position. Position 1 is the only
exception: its predecessor is the anchor, so it needs just one. The counts are therefore:

```
multiply-adds:  (B-1) * top_k^2                      one per (position, predecessor, candidate)
exponentials:   top_k + (B-2) * top_k^2              one softmax per (position, predecessor)
                <= B * top_k^2                       simple upper bound
```

At `B = 8`, `top_k = 10`: 610 `expf` calls exactly, 800 as the simple bound - **not 80**. The
exponential count tracks the multiply-add count rather than sitting a factor of `top_k` below it.

Where the wrong figure came from, since it is an easy mistake to repeat: `B * top_k` is **greedy's**
exponential count. Greedy evaluates one softmax per position, at the single chosen predecessor, and
only when `p_min > 0`. The DP evaluates the whole `(i, p)` grid. The "Numerics" note below already
said "per `(i, p)` slice" and so contradicted the cost line - that inconsistency was the tell.

**Does this change the "free" conclusion? No, and the argument is unchanged in substance.** Measured
at 4.9 microseconds per call at `B = 8`, `top_k = 10` on x86-64. Against the 23 ms draft step that is
**0.021%**. Even at the 20 microsecond bound P803 sets it is 0.087%. The DP remains free relative to
the GPU work by three orders of magnitude; only the analysis was wrong, not the conclusion. Nothing
in section 6.1's "zero GPU cost" claim or in the decision to prefer the DP depends on the corrected
figure.

Numerics: standard max-subtraction per `(i, p)` slice, exactly as the existing `p_min` code does. All
arithmetic in `float`. Ties break to the **lowest candidate index**, matching `std::max_element`'s
first-maximum behaviour, so greedy and DP agree on tie handling.

One normalization subtlety, stated so it is not "optimized" away: the softmax normalizer `Z_p` is
constant in `c`, so it does **not** affect the inner `argmax_c`. It is tempting to skip it. It cannot
be skipped, because `V_i(p)`'s **value** feeds the parent level, where values computed under
different predecessors are compared against each other and must be on a common scale. Drop the
normalization and the inner choice stays correct while every level above it silently becomes
meaningless.

### 6.6 Required behavioural properties

1. **`top_k == 1` reduces to current behaviour.** One candidate means `p_i(c|p) = 1` and the argmax
   is forced; DP and greedy emit the same sequence.
2. **The last position always agrees with greedy.** `V_B = 0`, so at `i = B-1` the DP maximizes
   `p_{B-1}(c|p)`, which is greedy's rule.
3. **Position 1's predecessor.** `score_run(1, 1, anchor_ids)` passes `n_pred == 1` and then
   `ggml_repeat_4d`s over `top_k` predecessor rows (`:530-532`), so row 1's transition block is
   identical for every `p`. Reading it at `p = 0` is correct; no special case is needed.
4. **Determinism.** No RNG, no threading, no reliance on floating-point reassociation.

### 6.7 Interaction with `p_min` and `n_min`

`p_min` stays a **post-selection truncation** with unchanged semantics, applied to the DP's chosen
path. It is deliberately **not** folded into the DP objective; folding it in would change two things
at once and make the greedy-vs-DP A/B unreadable.

With `p_min > 0` the DP may select a path that truncates earlier than greedy would even though its
unconstrained `E[L]` is higher. With `p_min == 0` - the GX10 setting, and section 9 says it stays -
the interaction is vacuous and the DP is a strict improvement under B-1..B-3.

`n_min` is untouched.

### 6.8 File layout and signatures

Logic in new files, existing files get call sites only.

**New: `common/speculative-dflash2.h`**

```cpp
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// DFlash2 selector lattice, as packed by build_dflash2_selector() in src/models/dflash.cpp.
// Row layout at each block position:
//   row[0 .. top_k-1]        candidate token ids, F32-cast
//   row[top_k + p*top_k + c] score of predecessor candidate p -> candidate c, unary logit of c included
// Block position 0 is a zero row and carries no draft token.
struct common_dflash2_lattice {
    const float * data   = nullptr; // row of block position 0
    size_t        stride = 0;       // floats between block positions
    int32_t       n_pos  = 0;       // block positions, including position 0
    int32_t       top_k  = 0;
};

// Reused across calls to keep the walk allocation-free after warmup.
struct common_dflash2_walk {
    std::vector<int32_t> idx;  // candidate index chosen at block positions 1 .. n_pos-1
    std::vector<float>   p;    // top_k-normalized acceptance probability of that choice
    std::vector<float>   work; // DP value table, [n_pos * top_k]
};

// Choose one candidate per block position.
// use_dp = false: greedy argmax per position, the historical behaviour.
// use_dp = true:  exact maximizer of the expected accepted prefix length.
// Fills res.idx and res.p with n_pos-1 entries. A degenerate lattice (n_pos < 2, top_k < 1,
// null data, or a non-finite score) yields empty res.idx and res.p.
void common_dflash2_walk_lattice(const common_dflash2_lattice & lat, bool use_dp, common_dflash2_walk & res);
```

**New: `common/speculative-dflash2.cpp`** - both walks plus the shared softmax helper. Includes only
its own header, `<cmath>` and `<vector>`: no llama, no ggml, no logging. Deliberate - it makes the
file linkable into a standalone unit test and keeps it out of the rebase blast radius. Registered in
`common/CMakeLists.txt` beside `speculative.cpp` (one line).

**Changed: `common/speculative.cpp`** - the `is_dflash2` block at `:1236-1263` becomes:

```
lat = { llama_get_embeddings_nextn(ctx_dft) + beg*n_embd_dec, n_embd_dec, n_block_tokens, selector_top_k }
common_dflash2_walk_lattice(lat, params.dflash2_dp, walk);
for j in 0 .. walk.idx.size()-1:
    if params.p_min > 0 and walk.p[j] < params.p_min: break
    id = (llama_token) lat.row(j+1)[walk.idx[j]]
    if id < 0 or id >= n_vocab_dft: SPC_WRN once; break
    result.push_back(id)
if result.size() < n_min: result.clear()
```

`walk` is a member of `common_speculative_impl_draft_dflash`; `n_vocab_dft` is cached in the
constructor.

### 6.9 The row-layout contract is undefended across a rebase

The row layout in 6.2 is a **contract between two files with no compile-time link**:
`build_dflash2_selector` (`src/models/dflash.cpp:475-565`) packs it and
`common/speculative-dflash2.cpp` unpacks it. Shape is guarded by
`GGML_ASSERT(res->t_logits->ne[1] == n_tokens)` and friends at `:486-487`, but **ordering is not**.
An upstream rebase that reorders the packing while preserving the shape - swapping the candidate-id
block and the transition block, or flipping the `p`-major convention at `row[top_k + p*top_k + c]` -
yields a lattice that parses cleanly, drafts plausible-looking tokens, and silently collapses
acceptance. **No assertion fires and nothing is logged.** This is the worst failure mode in the track
precisely because section 4 guarantees the output stays correct: the only symptom is throughput.

Two cheap defences:

1. **A cross-reference comment in both files**, each naming the other by path and stating that the
   layout is a contract. Upstream's comment at `src/models/dflash.cpp:474` already describes the
   packing; the fork adds the pointer to the consumer.
2. **A runtime canary on an invariant the layout implies but the shape does not.** At block position 1
   the predecessor is the anchor token, so `score_run(1, 1, anchor_ids)` passes `n_pred == 1` and
   `ggml_repeat_4d` (`:530-532`) makes row 1's transition block **identical for every predecessor
   `p`**. The consumer checks that `row_1[top_k + 0*top_k + c] == row_1[top_k + 1*top_k + c]` for all
   `c`, once per implementation instance on the first draft call, and `SPC_WRN`s if it does not. That
   invariant is a property of the packing order, so a reordering rebase breaks it, and it costs
   `top_k` float comparisons once per server lifetime.

The canary is a **warning, not a hard failure**: a false positive must not take the server down, and
a genuine layout change should be loud in the log rather than fatal in production.

### 6.9 Flag and default

Following `--spec-draft-backend-sampling` at `common/arg.cpp:4460-4467` exactly:

* `common/common.h`: `bool dflash2_dp = false;` in `common_params_speculative_draft` beside
  `backend_sampling` (`:332`).
* `common/arg.cpp`: `{"--spec-draft-dflash2-dp"} / {"--no-spec-draft-dflash2-dp"}`, `.set_spec()`,
  examples `{SPECULATIVE, SERVER, CLI}`, `.set_env("LLAMA_ARG_SPEC_DRAFT_DFLASH2_DP")`.
* `tools/server/tests/utils.py`: `spec_draft_dflash2_dp: bool | None = None` plus flag emission,
  matching `spec_draft_n_max` at `:142-143` and `:336-339`.
* One `LOG_INF` guarded by `is_dflash2` beside the existing init logging at `:994-998`.

**Default `false` (greedy).** The feature ships behaviour-identical; flipping the default is a
separate, measurement-gated feature (P805). This keeps "does the DP help" and "did we break the
draft" independently falsifiable.

## 7. Tree / multi-candidate drafting - feasibility

This is the **highest-ceiling item**, and it follows directly from the ~0.79 ms marginal verify cost:
the target can verify a tree of candidate paths for almost nothing. The selector already emits
`top_k` candidates per position plus the full `top_k x top_k` transition matrix, and the consumer
collapses all of it to one path and throws the rest away.

### 7.1 What llama.cpp can already express

**The batch and attention machinery can represent a tree, with no ggml change.** The standard
encoding gives each tree node the set of seq_ids of all leaves beneath it, so siblings never share a
seq_id. Checked against `llama_batch_allocr::validate`:

* **Partial-subset rule** (`src/llama-batch.cpp:336-386`) does `cur_seq_set[seq_id] &= seq_set[i]` and
  fails if the running intersection empties. A tree's leaf-seq-id family is **laminar** (any two
  seq-sets are nested or disjoint), which satisfies it. The invalid example in that comment is a
  non-laminar overlap, which a tree never produces.
* **Continuity rule** (`:316`) compares `seq_pos_max - seq_pos_min + 1` against `seq_pos[s].size()`,
  and `seq_pos[s]` is a **set** (`src/llama-batch.h:155`), so siblings at the same position collapse
  and do not trip it - provided siblings never share a seq_id, which the encoding guarantees.
* **Coupling rule** (`:326-333`): multi-seq tokens set `seq_cpl`, and coupled sequences must have
  identical `seq_pos_min/max` in memory. So the leaf sequences must be kept in lockstep, which means
  pruning and re-syncing every leaf after each acceptance via `seq_rm`/`seq_cp`. Real bookkeeping,
  but expressible.
* `LLAMA_MAX_SEQ` is 256 (`src/llama-cparams.h:8`), not a limit at this scale.

### 7.2 The KV-cache question, and why it is NOT a blocker

**Correction.** An earlier revision of this document claimed `kv-unified: false` was a hard collision
and that the tree project was blocked on an irreversible deployment constraint. **That was wrong.**
The mechanism it described is real; the mitigation already exists in this tree and was missed.

The mechanism: `n_stream = unified ? 1 : n_seq_max` (`src/llama-kv-cache.cpp:84`) and
`cparams.n_ctx_seq = cparams.n_ctx / cparams.n_seq_max` (`src/llama-context.cpp:293`). Under a
**non-unified** cache every additional seq_id allocates a full additional KV stream, so tree leaves
would multiply KV memory. Under a **unified** cache `n_stream = 1` and extra seq_ids cost only the
cells they occupy - a few dozen for a small tree. Tree drafting therefore wants `kv-unified: true`.

What was missed is **`--kv-unified-per-slot`**, merged as `18443257a` ("server: add ctx-per-slot",
#24124), which predates the commit this document is verified against:

* `common/common.h:630` - `int32_t kv_unified_per_slot = 0; // max context per parallel slot; 0 = unset`
* `common/arg.cpp:1718-1724` - the flag, `LLAMA_ARG_KV_UNIFIED_PER_SLOT`, server-only
* `tools/server/server.cpp:165-173` - when set **and `-c` is unset**,
  `params.n_ctx = params.n_parallel * params.kv_unified_per_slot`
* `tools/server/server-context.cpp:1229-1230` -
  `n_ctx_capped = kv_unified_per_slot > 0 ? min(n_ctx_seq, kv_unified_per_slot) : n_ctx_seq`

This retraces the outage that motivated `kv-unified: false` to **advertised-context accounting, not
to unification itself**. Under `kv-unified: true` with no cap, every slot advertises the whole shared
pool - exactly the paired-500s failure mode. Under `kv-unified: true` plus
`--kv-unified-per-slot 98304`, the admission guarantee matches today's non-unified 6 x 98304 layout
while `n_stream` drops to 1.

Ops detail for whoever proposes the config change: `ctx_pool_auto_sized` at `server.cpp:165` requires
`params.n_ctx == 0`, so the pool is auto-sized **only when `-c` is unset**. A preset that pins `-c`
today must either unset it or pin it to `n_parallel * 98304 = 589824` explicitly. There is a warning
path at `server-context.cpp:1222-1226` for a cap exceeding per-slot pool capacity.

**What remains genuinely open** (OQ-T1, now a scoping question rather than a blocker): whether
`kv_unified_per_slot`'s admission accounting is expressed **per client slot** in a way that composes
with **multiple leaf seq-ids belonging to one logical slot**. Today `seq_id == slot.id` and the
mapping is 1:1; a tree breaks that, and whether the cap is enforced against cells-in-use per seq_id
or per slot decides whether a 4-leaf tree quietly consumes 4x a slot's advertised budget. That must
be answered before a tree implementation is scoped. It does not block the oracle measurement.

Flipping `kv-unified` on GX10 is a **live config change on a production box**, not a repo change,
tracked as an ops action in P808 requiring operator approval and a `models.ini.bak-YYYYMMDD-HHMMSS`
backup.

### 7.3 What blocks it in the plumbing

This is the real cost, and it is upstream-invasive in exactly the files this fork already pays to
rebase:

| Layer | Current shape | Needed |
|---|---|---|
| `common/speculative.h:71` | `llama_tokens * result` - a flat list | a tree (tokens plus a parent array); **public header** shared by all 8+ speculative implementations |
| `common/sampling.cpp:678` | `sample_and_accept_n`, asserts `idxs.size() == draft.size() + 1`, walks a chain | walk a tree, pick the accepted path |
| `tools/server/server-context.cpp:254` | `spec_draft` is `llama_tokens`, `spec_i_batch` a flat index list | tree-shaped both |
| `server-context.cpp:519-536` | `handle_last_sampled_token` assigns `pos0++` on the single seq `this->id` | sibling tokens at equal positions, per-node seq-id sets, a slot-to-seq-id **block** mapping instead of `seq_id == slot.id` |
| `server-context.cpp:541` | `prompt.tokens.insert(spec_draft)` absorbs the whole draft into the slot cache | insert only the accepted path |
| `server-context.cpp:3924-3960` | rollback via `keep_first` / `seq_rm` / checkpoint restore | prune non-accepted branches across all leaf seqs |

**Verdict: expressible at the llama/ggml layer without any ggml change; not expressible in the
current `common/` and server plumbing without changing a public header, the acceptance function, and
the server slot bookkeeping.** Rebase risk is **high** - `tools/server/` is refactored aggressively
and `common/speculative.h` is a shared public surface. This is a multi-feature project, not a patch.

One framing correction, because it changes how a mitigation should be sold: a formulation that keeps
`result` a flat list and passes the parent array out-of-band (OQ-T2) would avoid touching
`common/speculative.h`, but **`common_sampler_sample_and_accept_n` must change for a tree
regardless of where the parent array lives** - it breaks on first mismatch and walks a chain by
construction. `common/sampling.{h,cpp}` is as public a surface as `speculative.h`, with an
overlapping consumer set. So the honest description of that mitigation is **"avoids one of two
equally-shared files"**, not "reduces exposure to server bookkeeping alone".

### 7.4 The go/no-go experiment, which comes first

Before committing to any of that, measure the **ceiling**: a tree can at best accept a token that is
somewhere in the candidate set it expands. Instrument, on the existing greedy path, the per-position
rate at which the target's sampled token appears among the top `w` candidates, and compare against
the acceptance of the single chosen candidate:

```
oracle_w(i) = P(target's token at position i is among the top w candidates)
chosen(i)   = current per-position acceptance (section 3)
```

**Report `oracle_w(i)` for `w` in {2, 4, 8, 10}, and gate go/no-go on the width actually
implementable, not on `w = 10`.** A tree that expands all 10 candidates at every position is not a
realistic implementation target - the verify batch and the leaf seq-id count both grow with it. The
`w = 10` figure is the theoretical ceiling; the `w = 2` and `w = 4` figures are the ones a first
implementation could plausibly reach, and they are what the decision should rest on.

**Two upward biases, both of which must be stated with the number:**

1. **Truncated support.** `oracle_w` credits only candidates the selector emitted. That is the
   intended bound and is not a bias in the tree's favour.
2. **Branch-selection confound.** `oracle_w(i)` credits **set membership** and thereby assumes a
   perfect choice of which `w` candidates to expand and perfect handling of the resulting branch. A
   real tree must decide its expansion budget per position ahead of knowing the answer. So
   `oracle_w(i)` is an upper bound that **no implementation reaches**, and the gap is not
   quantifiable from this measurement. Treat it as a ceiling, never as a forecast.

**This is not a read-only measurement, and the earlier claim that it "needs no tree machinery at
all" was wrong.** `common_sampler_sample_and_accept_n` (`common/sampling.cpp:678-706`) **breaks on
first mismatch and never samples past it**, so the target's token at positions after the first
rejection does not exist and cannot be compared against anything. Collecting `oracle_w(i)` across all
positions requires a **scoped instrumentation patch** that continues sampling past the first
mismatch. That patch is not intended to be merged and belongs on a throwaway branch.

**The sampler-contamination trap, which decides whether the numbers are worth anything.** Sampling
past the first mismatch to collect a counterfactual **must use a cloned or scratch sampler**. The
production sampler chain carries repetition-penalty and DRY state that `common_sampler_accept`
mutates on every call. Advancing it through tokens that were never emitted corrupts that state,
changes the tokens the run actually produces, and therefore poisons the very `chosen(i)` baseline the
project is being decided against. The server already clones a sampler for exactly this reason at
`tools/server/server-context.cpp:3911` (`common_sampler_clone(slot.smpl.get())`); the instrumentation
must do the same and must assert that the emitted token stream is unchanged with instrumentation on
versus off.

That measurement is P809's first and only mandatory deliverable. All design work behind it is gated
on the number.

## 8. Long-context acceptance degradation

Position-1 acceptance falls from 0.830 to 0.638 as context grows, and the whole curve shifts down.
This is the single largest effect in the system and its cause is unknown.

What is already ruled out: **the draft context is not truncated.** `cparams.n_ctx = llama_n_ctx(ctx_tgt)`
(`common/speculative.cpp:2549`), so the draft context is sized to the target's.

Candidate causes worth separating:

1. **Workload difficulty**, not context length. Long Copilot prompts are large source files, where
   the next token is intrinsically less predictable than in a short synthetic prompt. This is the
   null hypothesis and it must be excluded before anything else is investigated.
2. **Stale or truncated injected target features.** DFlash injects `n_extract=5` target layers; if the
   injection covers only part of a long context, the draft's conditioning degrades with length.
3. **Checkpoint/replay churn.** `slot.spec_is_replay` and `ckpt.load_dft` restore draft state on
   partial acceptance (`server-context.cpp:3930-3958`). If replays get more frequent at long context,
   the draft may be running from restored rather than fresh state more often.

**The load-bearing experimental design:** cause 1 cannot be separated from causes 2 and 3 by
comparing short synthetic prompts against long real ones, because both the length and the content
change. The experiment must hold content fixed and vary only length - take one fixed continuation
task and prepend increasing amounts of **irrelevant** filler context, then measure the per-position
acceptance curve as a function of prefix length alone. If the curve is flat in filler length, the
degradation is workload difficulty and there is nothing to fix in the code; if it decays, the
mechanism is real and causes 2 and 3 become worth chasing.

That experiment is P810's mandatory first deliverable.

## 9. Decision record: `p_min` stays 0, `n_max` stays 7

**`p_min = 0`.** Truncating a draft is only worth doing if a shorter draft makes the target verify
step cheaper. The measurement says it barely does: the marginal verify cost is **~0.79 ms per draft
token** against an ~80 ms fixed target cost. Dropping a draft token saves 0.79 ms and costs real
accepted length - at long context, position-3 acceptance is 0.323, so a token dropped there forfeits
an expected ~0.32 accepted tokens worth ~25 ms of target time. Truncation loses by more than an order
of magnitude.

Conditions that would reverse this, so the claim is falsifiable:

* the verify step leaves the bandwidth-bound regime (6 slots aggregating into one target batch could
  do it; the ~0.79 ms figure is single-slot),
* a smaller or more heavily quantized target, where the weight read no longer dominates,
* draft KV pressure, which is not a constraint today.

**`n_max = 7`.** The sweep (29.26 / 34.35 / 40.19 t/s at n = 3 / 5 / 7, short ctx) is monotonic in
width, and width is nearly free at 0.79 ms/token. `n_max=7` is optimal and is capped only by the
checkpoint's `block_size=8`. This is a **validated finding**: the production setting is already
correct and needs no tuning. A larger `block_size` would need a different checkpoint.

**Speedup figures.** `/etc/llama-server/models.ini` on GX10 records a 3.37x speculative speedup. That
holds only at ctx 8192 with short prompts; production at 11k-98k context measures ~1.7-2.0x
(21-25 t/s against 12.4-13.0 t/s). Both numbers are real; neither is meaningful without its regime.
Correcting the deployed comment is an ops action, tracked in P808.

## 10. Measurement story - existing plumbing only

No new counters. Everything needed is already emitted:

| Signal | Source |
|---|---|
| draft microseconds per implementation (`dur(b,g,a)`, cumulative - divide by call count) | `common_speculative_print_stats`, `common/speculative.cpp:2953-2997`, `-lv 4` |
| mean accepted length, per-position acceptance | same function, `#mean acc len` and `#acc rate/pos` |
| per-slot acceptance and `acc per pos` | `tools/server/server-context.cpp:676-680` |
| target graph reuse | `llama_perf_context(ctx_tgt).n_reused`, `server-context.cpp:658` |
| draft graph reuse | `llama_perf_context(ctx_dft).n_reused` - **not printed today**; P801 adds one `SLT_INF` beside the existing one |

`t_draft_us` covers `llama_decode` and the CPU lattice walk together (the timer wraps the whole
`draft()` call at `:2832`). That is fine: the DP's cost is far below the noise floor, and the
interesting number for Lead B is `#mean acc len`, not `t_draft_us`.

Bench protocol. **There are two protocols, not one, and a single run cannot serve both.**

**Protocol A - throughput and acceptance (the default for P801, P805, P807, P809, P810).**

1. Fixed model pair, `--spec-draft-n-max 7`, `--spec-draft-p-min 0`, single slot, `-lv 4`.
2. **Production sampling: `temperature 1.0, top_p 0.95, top_k 20`.** This is the regime in which
   every number in section 3 was measured, and it is the only regime in which those numbers can be
   reproduced. Fixed seed, fixed generation length, 3 repetitions, median.
3. Two context regimes: **SHORT** (ctx 8192, short prompts - reproduces 12.96 t/s no-spec and
   43.2 t/s DFlash2 at mean accepted length 4.6) and **LONG** (a captured ~30k-token Copilot-shaped
   prompt - reproduces 12.43 t/s no-spec and ~25 t/s at mean accepted length 3.15).
4. Reported for every run: **t/s, acceptance rate, mean accepted length, and the full per-position
   acceptance vector.** The per-position vector is the primary signal for Lead B, because a change
   that trades position-1 acceptance for later-position acceptance is exactly what the DP is supposed
   to do, and mean length alone hides it.

**Protocol B - determinism (P804's byte-identical check, and nothing else).**

1. Same model pair and context regimes, but **`--temp 0` with a fixed seed and a fixed prompt**, so
   greedy target sampling makes the whole token stream reproducible and two builds can be compared
   token-for-token.
2. Its only output is pass/fail on byte-identity. **It produces no throughput or acceptance number
   that may be compared against section 3.**

Why they cannot be merged: acceptance is regime-dependent. Under greedy target sampling the draft
only has to match one fixed argmax token; under a stochastic draw it has to match the actual sample.
A `--temp 0` run will report materially different acceptance from section 3's figures, and reading
that as a reproduction failure would be a measurement error, not a defect.

Harness: `contrib/gx10-deploy/bench-dflash2.sh`, fork-local, beside the existing `troubleshoot.sh`.
It shells out to existing binaries and parses existing log lines; no C++, not a build target. It must
record which protocol produced each CSV row.

## 11. Error handling strategy

No security boundary here, so "fail closed" maps to **fail safe: degrade to unaccelerated generation,
never to a wrong or failed response**.

| Condition | Behaviour |
|---|---|
| degenerate lattice (`n_pos < 2`, `top_k < 1`, null pointer) | walk returns no indices; empty draft; generation proceeds unaccelerated |
| non-finite score in a transition row | that position and everything after is dropped; the prefix already chosen is kept |
| decoded token id outside `[0, n_vocab_dft)` | draft truncated there, `SPC_WRN` once per implementation instance |
| `--spec-draft-dflash2-dp` with a non-DFlash2 draft | silently ignored |
| selector shape assumptions violated after a rebase | existing `GGML_ASSERT`s at `src/models/dflash.cpp:486-487` fire at graph build, before any token is drafted |

No fallback-to-greedy-on-error inside the DP: a lattice bad enough to break the DP would produce
garbage through the greedy walk too.

## 12. Rebase exposure

| File | Kind | Risk |
|---|---|---|
| `common/speculative-dflash2.{h,cpp}` | new, fork-local | none |
| `common/CMakeLists.txt` | 1 line | low |
| `common/speculative.cpp` (walk call site) | ~20 lines in one block | medium |
| `common/common.h`, `common/arg.cpp` (flag) | ~12 lines, two spots | low |
| `common/speculative.cpp` (P807 sampler tidy-up) | ~4 lines in the constructor and `draft()` | low |
| `src/models/dflash.cpp` | **no change** - the `ggml_repeat` tidy-up was cut rather than pay a conflict in a function with three recent upstream commits (`662a0b012`, `cc231cb0d`, `b10f9ca58`) for an unmeasurable gain | none |
| `tools/server/server-context.cpp` (draft `n_reused`) | 1 line | low |
| `tests/CMakeLists.txt` + `tests/test-dflash2-walk.cpp` | 1 line + new file | low |
| `contrib/gx10-deploy/*` | fork-local | none |
| **tree drafting (P809, if it proceeds)** | `common/speculative.h` public header, `common/sampling.cpp`, server slot bookkeeping | **high** |

Note on `tests/test-dflash2-walk.cpp`: AGENTS.md says not to add files under `tests/` without
maintainer approval. The fork is exempt from the contribution rules, but the added line in
`tests/CMakeLists.txt` is a small permanent conflict point. The alternative - no unit test for the DP
- is worse, because the DP is the one piece of this track whose correctness is not observable from
throughput numbers. Flagged as OQ-2.

## 13. Implementation order and who can actually run each feature

```
P801 (bench harness + draft graph-reuse line)
  |
  +--> P803 (new file: DP + greedy walk, unit tested, not wired)   [can start immediately, no dep]
  |      +--> P804 (wire behind --spec-draft-dflash2-dp, default off)
  |             +--> P805 (A/B on both regimes, flip default only if the bar is met)
  |                    ^ conclusion is CONTINGENT on P810 - see below
  |
  +--> P809 (tree drafting: oracle-ceiling measurement FIRST, then design only if it justifies)
  |
  +--> P810 (long-context degradation: fixed-content varying-filler experiment)
  |
  +--> P807 (tidy-up: unused DFlash2 per-seq sampler) - low priority, any time
  |
  +--> P808 (deployment decision record + kv-unified ops proposal)

P802 - closed done-by-inspection (GGUF header parse). No work remains.
P806 - closed won't-do (top-k cost bounded far below the 3 ms gate). No work remains.
```

P803 has no dependency on P801 for correctness, only for measurement, so it can start immediately.
P809 and P810 are measurement-first and independent of the DP work; either can run in parallel.

**P805 and P810 interact and the ordering is deliberate.** P810 may ship a fix that moves
position-1 acceptance, and position 1 is exactly what the DP trades away. A P805 verdict reached
against today's curve could invert once P810 lands. Two options were available: sequence P805 strictly
after P810, or let P805 proceed with a contingent conclusion. **This design takes the contingent
option**, because P810 is an open-ended investigation whose most likely verdict is "workload
difficulty, nothing to fix", and blocking the track's primary near-term feature on an investigation
with no bounded end is a bad trade. The cost of that choice is a **mandatory re-run trigger**, written
into P805's acceptance criteria: if P810 ships any change that moves the position-1 acceptance figure,
P805's A/B is re-run and its default-flip decision re-evaluated before the result is treated as
settled.

### 13.1 Testability: what a test-runner agent can and cannot do

This matters for the workflow in CLAUDE.md, where `test-runner` executes suites and updates
features.json. **Most of this track is not pytest-executable.**

| Feature | Who can run it |
|---|---|
| P803 | **test-runner**. Pure CPU unit test, no GPU, no checkpoint, no server. |
| P804 | **split**. Build and the full existing server suite are test-runner work. The behavioural criteria - byte-identical drafts under Protocol B, per-position reproduction under Protocol A - are **operator-run on GX10** and need the real checkpoint plus a GPU. |
| P801, P805, P807, P808, P809, P810 | **operator on GX10 only.** No pytest harness can exercise them: the server test suite has no DFlash2 draft GGUF, and every acceptance number requires the real 16.46 GB target plus the 3.86 GB draft. |

A test-runner agent must not attempt the operator-only criteria. Left unmarked, it would run them,
find no draft model, and either fail silently or report a spurious pass. Each affected feature's
acceptance criteria state the executor explicitly.

**Bare `assert()` is compiled out of this project's Release build** (`-DNDEBUG`). A test file written
with `assert()` therefore passes unconditionally in Release while checking nothing. This is not
hypothetical: P803's first test file was written that way, and it was proved vacuous by sabotaging
`greedy_walk` to always return index 0 and observing the binary still print `All tests passed!`. All
41 assertions were replaced with an unconditional abort macro.

The consequence for this design: **any acceptance criterion anywhere in PR8 that leans on a unit test
to enforce something is only as good as that test's checks being unconditional.** Every such
criterion assumes a check that survives `-DNDEBUG`. Two rules follow, and they apply to P803 and to
any future PR8 feature that adds a test:

1. Test assertions use an unconditional macro that aborts regardless of `NDEBUG`, never bare
   `assert()`.
2. A new test is validated by **deliberately breaking the code under test and confirming the test
   fails.** A test that has never been seen to fail has not been shown to test anything.

## 14. Open questions, after the challenger pass

**Closed by measurement or by challenger ruling**, listed so they are not re-raised:

* old OQ-1 (is `E[L]` right net of draft cost) - yes; draft cost is flat in `n_max`.
* old OQ-4 (is 3 ms the right top-k gate) - moot; the cost is bounded far below it.
* old OQ-7 (a cheaper experiment than a bench cycle to separate lm_head from top-k) - the GGUF
  header parse was it, and it discriminated cleanly in favour of lm_head.
* old OQ-T1 as originally posed ("is `kv-unified: false` irreversible, and does it kill the tree
  project") - **wrong question, retracted.** `--kv-unified-per-slot` already exists
  (`18443257a`). See section 7.2. What survives is a narrower scoping question, restated below.
* old OQ-3 (what bar should P805 flip the default on) - **ruled**, see 14.1. It is now a design
  decision rather than an open question, and it is fixed before the A/B runs rather than after.

### 14.1 Ruled: P805's bar is stated on the per-position vector

The scalar mean accepted length is the wrong gate, because the DP's intended mechanism is a trade
*between* positions and a scalar mean can hide both a win and a regression. The bar is therefore
stated on the curve, with a floor on the position it is expected to sacrifice:

1. **Position-1 floor.** Position-1 acceptance regresses by **no more than 0.03 absolute** against
   the LONG baseline of 0.638. Position 1 is what the DP trades away, and it is also the value P810
   may move, so it gets an explicit floor rather than being absorbed into an average.
2. **Later-position gain.** The sum of per-position acceptance over positions **3 through 7**
   improves by at least **0.10 absolute** in the LONG regime (baseline sum:
   0.323 + 0.236 + 0.189 + 0.142 + 0.110 = 1.000).
3. **No throughput regression.** No t/s regression beyond 2% in either regime.

Mean accepted length and t/s are still reported, but they are outcomes, not the gate. All three
conditions must hold. This text is fixed **before** the A/B runs.

### 14.2 Still genuinely open

**OQ-1 (informative, no longer blocking P803).** Assumption B-2's over-estimate is argued to be
common to all paths through a position, but the DP multiplies across positions, so differing
mass-capture between an early and a late position could skew path ranking. **Downgraded from
blocking** on the challenger's reasoning: P805 gates on the measured per-position curve, not on the
DP's internal belief, so a gain that exists only inside a mis-calibrated model simply fails to appear
and the default is not flipped. The failure mode is a wasted A/B, not a shipped regression. It
remains worth a view because it **informs 14.1**: if calibration skew is expected to be large, the
later-position threshold should be less generous. P803 carries an adversarial unit test for it - a
hand-written lattice with deliberately mismatched mass-capture between an early and a late position,
asserting the DP never scores worse than greedy under the design's own objective.

**OQ-2 (binding, blocks P803).** Placement of the DP unit test: a new `tests/test-dflash2-walk.cpp`
plus one line in `tests/CMakeLists.txt`, against AGENTS.md's no-new-files-under-`tests/` rule and the
perpetual rebase. Alternatives: a fork-local target under `contrib/`, or folding the checks into an
existing test binary. This is the only remaining question that blocks a coder from starting.

**OQ-T1, restated (blocks scoping a tree implementation; does NOT block P809's measurement).** Is
`kv_unified_per_slot`'s admission accounting expressed **per client slot** in a way that composes
with **multiple leaf seq-ids belonging to one logical slot**? Today `seq_id == slot.id` and the
mapping is 1:1. Whether the cap is enforced against cells-in-use per seq_id or per slot decides
whether a 4-leaf tree quietly consumes 4x a slot's advertised budget - which is the same
advertised-context accounting failure that caused the original outage, re-entering through a
different door.

**OQ-T2, reframed (non-binding, informs P809 scope).** A formulation keeping `result` a flat list
with an out-of-band parent array would avoid changing `common/speculative.h` - but
`common_sampler_sample_and_accept_n` must change for a tree regardless, and `common/sampling.{h,cpp}`
is an equally public surface with an overlapping consumer set. The honest question is therefore
whether **avoiding one of two equally-shared files** is worth the added indirection, not whether it
reduces exposure to server bookkeeping alone.

**OQ-4 (non-binding).** P807's surviving tidy-up skips the per-seq `common_sampler` allocation when
`is_dflash2`. Is a conditional allocation worth the branch in a constructor upstream may restructure,
or is 12 MB across 6 slots simply not worth touching?

**OQ-5 (new, for P809; likely already answered - needs confirmation, not invention).** Section 7.4
says the oracle measurement needs an instrumentation patch that samples past the first mismatch with
a cloned sampler. **That may be avoidable entirely.** The server adds every draft token to the target
batch with `output = true`:

* `tools/server/server-context.cpp:533` - `batch.add(this->id, token, pos0++, true, false)`
* `tools/server/server-context.cpp:156` - `bool add(int32_t id_slot, llama_token token, llama_pos pos, bool output, bool is_prompt)`

So the target **already computes full logits at every draft position**, including positions after the
first mismatch, and they are retrievable through `llama_get_logits_ith(ctx_tgt, slot.spec_i_batch[i])`
with **no extra sampling, no counterfactual continuation, and no sampler-state mutation**. That
removes the contamination trap completely and makes the measurement genuinely read-only.

The caveat that must be checked before relying on it: those logits are conditioned on **the drafted
prefix**, which after the first mismatch is not the sequence the target would have produced on its
own. For evaluating a tree that expands *that same branch* this is exactly the right conditioning.
For a tree that expands a *different* branch at an earlier position it is not, and the counterfactual
continuation would still be needed for those shapes. So the question for the challenger is narrower
than originally posed: **does reading the existing per-position target logits suffice for the `w` in
{2, 4} decision, or only for the along-the-drafted-path subset of it?** If it suffices, P809's
instrumentation patch and its entire contamination risk disappear, and the measurement becomes a
buffer read.
