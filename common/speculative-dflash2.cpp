#include "speculative-dflash2.h"

#include <cmath>

// Softmax over top_k candidates with max-subtraction for numerical stability.
// Stores the softmax into p_out and returns the selected index (argmax).
static int32_t softmax_and_argmax(const float * scores, int32_t top_k, float * p_out) {
    // Find max for numerical stability
    float s_max = scores[0];
    for (int32_t k = 1; k < top_k; ++k) {
        if (scores[k] > s_max) {
            s_max = scores[k];
        }
    }

    // Compute exp and sum
    float sum = 0.0f;
    for (int32_t k = 0; k < top_k; ++k) {
        p_out[k] = std::exp(scores[k] - s_max);
        sum += p_out[k];
    }

    // Normalize
    float inv_sum = 1.0f / sum;
    for (int32_t k = 0; k < top_k; ++k) {
        p_out[k] *= inv_sum;
    }

    // Find argmax (first maximum for tie-breaking to lowest index)
    int32_t argmax = 0;
    for (int32_t k = 1; k < top_k; ++k) {
        if (scores[k] > scores[argmax]) {
            argmax = k;
        }
    }

    return argmax;
}

// Greedy walk: predecessor starts at 0, argmax over top_k transition scores at each position.
// Tie-breaks to the lowest index (std::max_element first-maximum semantics).
static void greedy_walk(const common_dflash2_lattice & lat, common_dflash2_walk & res) {
    res.idx.clear();
    res.p.clear();

    if (lat.n_pos < 2 || lat.top_k < 1 || lat.data == nullptr) {
        return;
    }

    res.idx.reserve(lat.n_pos - 1);
    res.p.reserve(lat.n_pos - 1);

    int32_t predecessor = 0;
    for (int32_t i = 1; i < lat.n_pos; ++i) {
        const float * row = lat.data + (size_t)i * lat.stride;
        const float * scores = row + lat.top_k + (size_t)predecessor * lat.top_k;

        // Check for non-finite scores
        bool has_non_finite = false;
        for (int32_t k = 0; k < lat.top_k; ++k) {
            if (!std::isfinite(scores[k])) {
                has_non_finite = true;
                break;
            }
        }
        if (has_non_finite) {
            break;
        }

        float p_temp[16]; // Stack buffer for softmax, sufficient for typical top_k <= 16
        predecessor = softmax_and_argmax(scores, lat.top_k, p_temp);
        res.idx.push_back(predecessor);
        res.p.push_back(p_temp[predecessor]);
    }
}

// DP walk: compute the backward recurrence and reconstruct the optimal path forward.
// Cost: n_pos*top_k*top_k multiply-adds, matching design section 6.5. The expf count is
// n_pos*top_k*top_k for the backward pass (a distinct softmax normalization is required per
// predecessor p, since each predecessor's row has its own transition scores) plus n_pos*top_k
// for the forward reconstruction, i.e. dominated by n_pos*top_k^2 rather than n_pos*top_k -
// still on the order of a microsecond at n_pos=8, top_k=10, but design section 6.5's stated
// "B * top_k exponentials" undercounts the backward pass; flagged for the architect.
static void dp_walk(const common_dflash2_lattice & lat, common_dflash2_walk & res) {
    res.idx.clear();
    res.p.clear();

    if (lat.n_pos < 2 || lat.top_k < 1 || lat.data == nullptr) {
        return;
    }

    res.idx.reserve(lat.n_pos - 1);
    res.p.reserve(lat.n_pos - 1);

    // Work buffer: V[i][p] at offset i * top_k + p, for i in [1, n_pos-1], p in [0, top_k)
    int32_t work_size = lat.n_pos * lat.top_k;
    if ((int32_t)res.work.size() < work_size) {
        res.work.resize(work_size);
    }
    float * V = res.work.data();

    // Backward pass: compute V[i][p] for i = n_pos-1 down to 1
    // V[n_pos][p] = 0 (implicit)
    // V[i][p] = max_c p_i(c|p) * (1 + V[i+1][c])
    for (int32_t i = lat.n_pos - 1; i >= 1; --i) {
        const float * row = lat.data + (size_t)i * lat.stride;

        for (int32_t p = 0; p < lat.top_k; ++p) {
            const float * scores = row + lat.top_k + (size_t)p * lat.top_k;

            // Check for non-finite scores
            bool has_non_finite = false;
            for (int32_t k = 0; k < lat.top_k; ++k) {
                if (!std::isfinite(scores[k])) {
                    has_non_finite = true;
                    break;
                }
            }
            if (has_non_finite) {
                V[i * lat.top_k + p] = 0.0f;
                continue;
            }

            // Softmax with max-subtraction
            float s_max = scores[0];
            for (int32_t k = 1; k < lat.top_k; ++k) {
                if (scores[k] > s_max) {
                    s_max = scores[k];
                }
            }

            float sum = 0.0f;
            float best_val = -1e10f;
            for (int32_t c = 0; c < lat.top_k; ++c) {
                float exp_val = std::exp(scores[c] - s_max);
                sum += exp_val;

                // V[i+1][c] is only valid for i+1 < n_pos
                float tail_val = (i + 1 < lat.n_pos) ? V[(i + 1) * lat.top_k + c] : 0.0f;
                float val = exp_val * (1.0f + tail_val);
                if (val > best_val) {
                    best_val = val;
                }
            }

            if (sum > 0.0f) {
                V[i * lat.top_k + p] = best_val / sum;
            } else {
                V[i * lat.top_k + p] = 0.0f;
            }
        }
    }

    // Forward reconstruction: choose candidates c_1, c_2, ..., c_{n_pos-1}
    // c_1 = argmax_c p_1(c | 0) * (1 + V_2(c))
    // c_i = argmax_c p_i(c | c_{i-1}) * (1 + V_{i+1}(c))

    int32_t predecessor = 0;
    for (int32_t i = 1; i < lat.n_pos; ++i) {
        const float * row = lat.data + (size_t)i * lat.stride;
        const float * scores = row + lat.top_k + (size_t)predecessor * lat.top_k;

        // Check for non-finite scores
        bool has_non_finite = false;
        for (int32_t k = 0; k < lat.top_k; ++k) {
            if (!std::isfinite(scores[k])) {
                has_non_finite = true;
                break;
            }
        }
        if (has_non_finite) {
            break;
        }

        // Softmax with max-subtraction
        float s_max = scores[0];
        for (int32_t k = 1; k < lat.top_k; ++k) {
            if (scores[k] > s_max) {
                s_max = scores[k];
            }
        }

        float sum = 0.0f;
        float best_val = -1e10f;
        int32_t best_c = 0;

        for (int32_t c = 0; c < lat.top_k; ++c) {
            float exp_val = std::exp(scores[c] - s_max);
            sum += exp_val;

            // V[i+1][c] is only valid for i+1 < n_pos
            float tail_val = (i + 1 < lat.n_pos) ? V[(i + 1) * lat.top_k + c] : 0.0f;
            float val = exp_val * (1.0f + tail_val);
            if (val > best_val) {
                best_val = val;
                best_c = c;
            }
        }

        predecessor = best_c;
        if (sum > 0.0f) {
            res.p.push_back(std::exp(scores[best_c] - s_max) / sum);
        } else {
            res.p.push_back(0.0f);
        }
        res.idx.push_back(predecessor);
    }
}

void common_dflash2_walk_lattice(const common_dflash2_lattice & lat, bool use_dp, common_dflash2_walk & res) {
    if (use_dp) {
        dp_walk(lat, res);
    } else {
        greedy_walk(lat, res);
    }
}

// Helper to check the position-1 canary invariant for the unit test.
// Returns true if the invariant holds (all comparisons equal), false if violated.
bool common_dflash2_check_pos1_canary(const common_dflash2_lattice & lat) {
    // Check if position 1 exists and has sufficient data. top_k < 2 means there is no
    // predecessor index 1 to compare against, so the invariant is vacuous.
    if (lat.n_pos < 2 || lat.top_k < 2 || lat.data == nullptr) {
        return true; // Degenerate lattice, no canary to check
    }

    const float * row1 = lat.data + lat.stride;

    // At position 1, the predecessor is the anchor token (one id per sequence).
    // ggml_repeat_4d makes row 1's transition block identical for every predecessor p.
    // So we check that row_1[top_k + 0*top_k + c] == row_1[top_k + 1*top_k + c] for all c.
    for (int32_t c = 0; c < lat.top_k; ++c) {
        float val0 = row1[lat.top_k + 0 * lat.top_k + c];
        float val1 = row1[lat.top_k + 1 * lat.top_k + c];
        if (val0 != val1) {
            return false; // Canary violated
        }
    }

    return true; // Canary holds
}
