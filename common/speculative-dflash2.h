#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// DFlash2 selector lattice, as packed by build_dflash2_selector() in src/models/dflash.cpp.
// Row layout at each block position:
//   row[0 .. top_k-1]        candidate token ids, F32-cast
//   row[top_k + p*top_k + c] score of predecessor candidate p -> candidate c, unary logit of c included
// Block position 0 is a zero row and carries no draft token.
//
// Probability model assumptions:
// B-1: per-position acceptance probability of candidate c given predecessor p is the softmax
//      over the top_k transition scores.
// B-2: mass outside the top_k candidates is unmodelled (treated as zero), so the softmax
//      over-estimates the true acceptance probability.
// B-3: given the chosen path, acceptance events at successive positions are conditionally
//      independent, so the probability of accepting the first i drafted tokens is the product
//      of per-position probabilities.
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

// Check the position-1 canary invariant: row_1[top_k + 0*top_k + c] == row_1[top_k + 1*top_k + c]
// for all c in [0, top_k). This invariant holds when the row is laid out by ggml_repeat_4d with
// n_pred == 1 (position 1's predecessor is the anchor token). Returns true if the invariant holds,
// false if violated. Used primarily by unit tests to verify the layout contract.
bool common_dflash2_check_pos1_canary(const common_dflash2_lattice & lat);
