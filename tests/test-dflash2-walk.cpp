#include "speculative-dflash2.h"

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <random>
#include <vector>

// Plain assert() is compiled out under NDEBUG, and this project's default build type (Release,
// see the top-level CMakeLists.txt) defines it. That would silently turn every check below into
// a no-op and make this binary "pass" regardless of correctness. Use a check that always runs.
#define DF2_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "CHECK FAILED: " #cond << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::abort(); \
        } \
    } while (0)

// Helper: compute E[L] for a given path through the lattice
static float compute_expected_length(const std::vector<float> & lattice, int top_k, size_t stride,
                                     const std::vector<int32_t> & path) {
    float expected = 0.0f;
    float prob_prefix = 1.0f;

    for (size_t i = 0; i < path.size(); ++i) {
        int pred = (i == 0) ? 0 : path[i - 1];
        int cand = path[i];
        size_t pos = i + 1; // position 1 to n_pos-1

        // Get the row
        const float * row = lattice.data() + pos * stride;
        const float * scores = row + top_k + (size_t)pred * top_k;

        // Compute softmax
        float s_max = scores[0];
        for (int k = 1; k < top_k; ++k) {
            if (scores[k] > s_max) s_max = scores[k];
        }
        float sum = 0.0f;
        for (int k = 0; k < top_k; ++k) {
            sum += std::exp(scores[k] - s_max);
        }
        float prob_c = std::exp(scores[cand] - s_max) / sum;

        prob_prefix *= prob_c;
        expected += prob_prefix;
    }

    return expected;
}

// Test: Greedy equivalence to the original loop at speculative.cpp:1240-1256
static void test_greedy_equivalence() {
    std::cout << "Test: Greedy equivalence..." << std::endl;

    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-5.0f, 5.0f);

    int num_tests = 1000;
    for (int test_idx = 0; test_idx < num_tests; ++test_idx) {
        int top_k = 2 + rng() % 15; // 2..16
        int n_pos = 2 + rng() % 8;  // 2..9

        // Generate random lattice
        std::vector<float> lattice_data;
        for (int pos = 0; pos < n_pos; ++pos) {
            for (int tok = 0; tok < top_k; ++tok) {
                lattice_data.push_back((float)tok); // candidate ids
            }
            for (int p = 0; p < top_k; ++p) {
                for (int c = 0; c < top_k; ++c) {
                    lattice_data.push_back(dist(rng)); // transition scores
                }
            }
            // Padding
            size_t n_embd_dec = 128; // arbitrary
            while (lattice_data.size() % n_embd_dec != 0) {
                lattice_data.push_back(0.0f);
            }
        }

        // Compute greedy path (manual inline implementation)
        std::vector<int32_t> expected_path;
        int32_t predecessor = 0;
        for (int32_t i = 1; i < n_pos; ++i) {
            size_t row_start = (size_t)i * 128;
            const float * scores = lattice_data.data() + row_start + top_k + (size_t)predecessor * top_k;

            // Find argmax (first maximum for tie-breaking)
            int32_t argmax = 0;
            for (int k = 1; k < top_k; ++k) {
                if (scores[k] > scores[argmax]) {
                    argmax = k;
                }
            }
            predecessor = argmax;
            expected_path.push_back(argmax);
        }

        // Compute using the library
        common_dflash2_lattice lat{
            lattice_data.data(),
            128,
            (int32_t)n_pos,
            (int32_t)top_k
        };
        common_dflash2_walk walk;
        common_dflash2_walk_lattice(lat, false, walk);

        // Compare
        DF2_CHECK(walk.idx.size() == expected_path.size());
        for (size_t i = 0; i < walk.idx.size(); ++i) {
            DF2_CHECK(walk.idx[i] == expected_path[i] && "Greedy path mismatch");
        }
    }

    std::cout << "  PASS: 1000 greedy paths match" << std::endl;
}

// Test: top_k == 1 reduction
static void test_top_k_one() {
    std::cout << "Test: top_k == 1 reduction..." << std::endl;

    for (int n_pos = 2; n_pos <= 6; ++n_pos) {
        std::vector<float> lattice_data;
        for (int pos = 0; pos < n_pos; ++pos) {
            lattice_data.push_back(0.0f); // candidate id
            lattice_data.push_back(1.5f); // transition score
            for (int i = 0; i < 126; ++i) {
                lattice_data.push_back(0.0f); // padding
            }
        }

        common_dflash2_lattice lat{
            lattice_data.data(),
            128,
            (int32_t)n_pos,
            1
        };

        common_dflash2_walk walk_greedy;
        common_dflash2_walk_lattice(lat, false, walk_greedy);

        common_dflash2_walk walk_dp;
        common_dflash2_walk_lattice(lat, true, walk_dp);

        DF2_CHECK(walk_greedy.idx.size() == (size_t)(n_pos - 1));
        DF2_CHECK(walk_dp.idx.size() == (size_t)(n_pos - 1));

        for (size_t i = 0; i < walk_greedy.idx.size(); ++i) {
            DF2_CHECK(walk_greedy.idx[i] == 0 && "top_k=1 should always choose 0");
            DF2_CHECK(walk_dp.idx[i] == 0 && "top_k=1 DP should always choose 0");
            DF2_CHECK(walk_greedy.p[i] == 1.0f && "top_k=1 probability should be 1.0");
            DF2_CHECK(walk_dp.p[i] == 1.0f && "top_k=1 DP probability should be 1.0");
        }
    }

    std::cout << "  PASS: top_k=1 produces all-zeros idx and all-1.0 probabilities" << std::endl;
}

// Reference greedy argmax over a single predecessor's transition block, independent of the
// implementation under test. Mirrors common/speculative.cpp:1240-1246's tie-break-to-lowest-index.
static int32_t ref_argmax(const float * row, int top_k, int pred) {
    const float * scores = row + top_k + (size_t)pred * top_k;
    int32_t argmax = 0;
    for (int k = 1; k < top_k; ++k) {
        if (scores[k] > scores[argmax]) {
            argmax = k;
        }
    }
    return argmax;
}

// Test: Last position agreement
//
// The stated property: for every test lattice, DP and greedy agree on the choice at block
// position n_pos-1, because V at position n_pos is zero (so the DP's per-position maximization
// there reduces exactly to greedy's argmax rule). This is tested directly: position n_pos-2 is
// set to an overwhelming, predecessor-independent score for a chosen "target_pred" candidate, so
// both walks are forced to arrive at the last position with the SAME predecessor regardless of
// whatever they did at earlier (randomized) positions. Given that shared predecessor, both walks
// must then choose the same candidate at the last position.
static void test_last_position_agreement() {
    std::cout << "Test: Last position agreement..." << std::endl;

    std::mt19937 rng(123);
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    std::uniform_real_distribution<float> last_dist(-4.0f, 4.0f);

    for (int test_idx = 0; test_idx < 200; ++test_idx) {
        int top_k = 2 + rng() % 8;
        int n_pos = 4 + rng() % 4; // >= 4 so there is a free position, a forcing position, and a last position
        int target_pred = rng() % top_k;

        std::vector<float> lattice_data(n_pos * 128, 0.0f);

        // Position 1 .. n_pos-3: unconstrained random rows (candidate ids + random transitions).
        for (int pos = 1; pos <= n_pos - 3; ++pos) {
            float * row = lattice_data.data() + (size_t)pos * 128;
            for (int tok = 0; tok < top_k; ++tok) {
                row[tok] = (float) tok;
            }
            for (int p = 0; p < top_k; ++p) {
                for (int c = 0; c < top_k; ++c) {
                    row[top_k + p * top_k + c] = dist(rng);
                }
            }
        }

        // Position n_pos-2: forced convergence. Every predecessor block scores target_pred at
        // +50 and everything else at -50, so regardless of the predecessor entering this
        // position, both greedy and DP are overwhelmingly certain to choose target_pred. The
        // bound (1 + V_{n_pos-1}(c)) is at most n_pos for any c, so a near-1.0 local probability
        // dominates any finite alternative.
        {
            float * row = lattice_data.data() + (size_t)(n_pos - 2) * 128;
            for (int tok = 0; tok < top_k; ++tok) {
                row[tok] = (float) tok;
            }
            for (int p = 0; p < top_k; ++p) {
                for (int c = 0; c < top_k; ++c) {
                    row[top_k + p * top_k + c] = (c == target_pred) ? 50.0f : -50.0f;
                }
            }
        }

        // Position n_pos-1 (last): arbitrary random scores, distinguishable argmax.
        {
            float * row = lattice_data.data() + (size_t)(n_pos - 1) * 128;
            for (int tok = 0; tok < top_k; ++tok) {
                row[tok] = (float) tok;
            }
            for (int p = 0; p < top_k; ++p) {
                for (int c = 0; c < top_k; ++c) {
                    row[top_k + p * top_k + c] = last_dist(rng);
                }
            }
        }

        common_dflash2_lattice lat{
            lattice_data.data(),
            128,
            (int32_t)n_pos,
            (int32_t)top_k
        };

        common_dflash2_walk walk_greedy;
        common_dflash2_walk_lattice(lat, false, walk_greedy);

        common_dflash2_walk walk_dp;
        common_dflash2_walk_lattice(lat, true, walk_dp);

        DF2_CHECK(walk_greedy.idx.size() == (size_t)(n_pos - 1));
        DF2_CHECK(walk_dp.idx.size() == (size_t)(n_pos - 1));

        // Both walks must have been forced through target_pred at position n_pos-2.
        DF2_CHECK(walk_greedy.idx[n_pos - 3] == target_pred && "greedy was not forced to target_pred");
        DF2_CHECK(walk_dp.idx[n_pos - 3] == target_pred && "DP was not forced to target_pred");

        // Given that identical predecessor, both walks must agree at the last position, and both
        // must match the independent reference argmax rule for that predecessor.
        const float * last_row = lattice_data.data() + (size_t)(n_pos - 1) * 128;
        int32_t expected_last = ref_argmax(last_row, top_k, target_pred);

        DF2_CHECK(walk_greedy.idx[n_pos - 2] == expected_last && "greedy disagrees with reference at last position");
        DF2_CHECK(walk_dp.idx[n_pos - 2] == expected_last && "DP disagrees with reference at last position");
        DF2_CHECK(walk_greedy.idx[n_pos - 2] == walk_dp.idx[n_pos - 2] &&
               "DP and greedy must agree at the last position given the same predecessor");
    }

    std::cout << "  PASS: given the same predecessor, DP and greedy agree at the last position" << std::endl;
}

// Test: DP optimality by brute force enumeration
static void test_dp_optimality() {
    std::cout << "Test: DP optimality (brute force for small top_k, n_pos)..." << std::endl;

    std::mt19937 rng(456);
    std::uniform_real_distribution<float> dist(-2.0f, 2.0f);

    for (int test_idx = 0; test_idx < 1000; ++test_idx) {
        int top_k = 2 + rng() % 3;  // 2..4
        int n_pos = 2 + rng() % 5;  // 2..6

        // Generate lattice
        std::vector<float> lattice_data(n_pos * 128);
        std::fill(lattice_data.begin(), lattice_data.end(), 0.0f);

        for (int pos = 0; pos < n_pos; ++pos) {
            for (int tok = 0; tok < top_k; ++tok) {
                lattice_data[pos * 128 + tok] = (float)tok;
            }
            for (int p = 0; p < top_k; ++p) {
                for (int c = 0; c < top_k; ++c) {
                    lattice_data[pos * 128 + top_k + p * top_k + c] = dist(rng);
                }
            }
        }

        common_dflash2_lattice lat{
            lattice_data.data(),
            128,
            (int32_t)n_pos,
            (int32_t)top_k
        };

        common_dflash2_walk walk_dp;
        common_dflash2_walk_lattice(lat, true, walk_dp);

        float dp_expected = 0.0f;
        {
            float prob_prefix = 1.0f;
            for (int pos = 1; pos < n_pos; ++pos) {
                int pred = (pos == 1) ? 0 : walk_dp.idx[pos - 2];
                int cand = walk_dp.idx[pos - 1];
                const float * row = lattice_data.data() + pos * 128;
                const float * scores = row + top_k + (size_t)pred * top_k;

                float s_max = scores[0];
                for (int k = 1; k < top_k; ++k) {
                    if (scores[k] > s_max) s_max = scores[k];
                }
                float sum = 0.0f;
                for (int k = 0; k < top_k; ++k) {
                    sum += std::exp(scores[k] - s_max);
                }
                float prob_c = std::exp(scores[cand] - s_max) / sum;
                prob_prefix *= prob_c;
                dp_expected += prob_prefix;
            }
        }

        // Brute force: enumerate all paths
        int path_len = n_pos - 1;
        int total_paths = 1;
        for (int i = 0; i < path_len; ++i) {
            total_paths *= top_k;
        }

        for (int path_enum = 0; path_enum < total_paths; ++path_enum) {
            std::vector<int32_t> path;
            int tmp = path_enum;
            for (int i = 0; i < path_len; ++i) {
                path.push_back(tmp % top_k);
                tmp /= top_k;
            }

            float path_expected = 0.0f;
            {
                float prob_prefix = 1.0f;
                for (int pos = 1; pos < n_pos; ++pos) {
                    int pred = (pos == 1) ? 0 : path[pos - 2];
                    int cand = path[pos - 1];
                    const float * row = lattice_data.data() + pos * 128;
                    const float * scores = row + top_k + (size_t)pred * top_k;

                    float s_max = scores[0];
                    for (int k = 1; k < top_k; ++k) {
                        if (scores[k] > s_max) s_max = scores[k];
                    }
                    float sum = 0.0f;
                    for (int k = 0; k < top_k; ++k) {
                        sum += std::exp(scores[k] - s_max);
                    }
                    float prob_c = std::exp(scores[cand] - s_max) / sum;
                    prob_prefix *= prob_c;
                    path_expected += prob_prefix;
                }
            }

            // DP's path should be >= all paths, within 1e-5 relative tolerance
            float rel_tol = 1e-5f;
            float abs_tol = 1e-10f;
            bool ok = (dp_expected >= path_expected - abs_tol)
                   || (dp_expected / (path_expected + 1e-20f) >= 1.0f - rel_tol);
            DF2_CHECK(ok && "DP did not find optimal path");
        }

        // Also check that DP >= greedy
        common_dflash2_walk walk_greedy;
        common_dflash2_walk_lattice(lat, false, walk_greedy);

        float greedy_expected = 0.0f;
        {
            float prob_prefix = 1.0f;
            for (int pos = 1; pos < n_pos; ++pos) {
                int pred = (pos == 1) ? 0 : walk_greedy.idx[pos - 2];
                int cand = walk_greedy.idx[pos - 1];
                const float * row = lattice_data.data() + pos * 128;
                const float * scores = row + top_k + (size_t)pred * top_k;

                float s_max = scores[0];
                for (int k = 1; k < top_k; ++k) {
                    if (scores[k] > s_max) s_max = scores[k];
                }
                float sum = 0.0f;
                for (int k = 0; k < top_k; ++k) {
                    sum += std::exp(scores[k] - s_max);
                }
                float prob_c = std::exp(scores[cand] - s_max) / sum;
                prob_prefix *= prob_c;
                greedy_expected += prob_prefix;
            }
        }

        DF2_CHECK(dp_expected >= greedy_expected - 1e-10f && "DP should beat or tie greedy");
    }

    std::cout << "  PASS: DP achieves at least greedy's E[L] over 1000 lattices" << std::endl;
}

// Test: DP beats greedy on a hand-written lattice
//
// This is the case the feature exists for: a locally weaker first step that opens a much
// stronger continuation. top_k = 2, n_pos = 3 (path length 2).
//
// Position 1, from the anchor (pred 0): scores [0.1, -0.1].
//   softmax: p(0|0) = 0.549834, p(1|0) = 0.450166. Greedy prefers candidate 0 (locally, by a
//   small margin), matching argmax of the raw scores.
// Position 2 (last):
//   From pred 0 (greedy's choice): scores [0, 0] -> tie, softmax 0.5/0.5, so V_2(0) = 0.5.
//   From pred 1 (the road not taken): scores [10, -10] -> softmax ~= 1.0, so V_2(1) ~= 1.0.
//
// V_1(0) = p(0|0) * (1 + V_2(0)) = 0.549834 * 1.5      = 0.824751
// V_1(1) = p(1|0) * (1 + V_2(1)) = 0.450166 * ~2.0      = 0.900332
//
// V_1(1) > V_1(0), so the DP picks candidate 1 at position 1 even though it is locally weaker,
// because it opens the far more confident position-2 continuation. Greedy is stuck with
// candidate 0 at position 1 and can only reach E[L] = 0.824751 there, while the DP reaches
// E[L] = 0.900332 (see the constant CHECK below, independently derived from the two probability
// chains). This matches the DP's own computed value V_1(0)'s counterpart V_1(1) by construction.
static void test_dp_beats_greedy() {
    std::cout << "Test: DP strictly beats greedy on hand-written lattice..." << std::endl;

    const int top_k = 2;
    const int n_pos = 3;

    std::vector<float> lattice_data(n_pos * 128);
    std::fill(lattice_data.begin(), lattice_data.end(), 0.0f);

    // Position 0: dummy, never read.

    // Position 1: candidate ids [0, 1]; transition block is uniform across predecessors
    // (ggml_repeat_4d makes it so in the real lattice, since position 1's predecessor is always
    // the anchor). Only p = 0 is ever read here, but both blocks are filled identically.
    lattice_data[0] = 0.0f;
    lattice_data[1] = 1.0f;
    for (int p = 0; p < top_k; ++p) {
        lattice_data[128 + top_k + p * top_k + 0] = 0.1f;
        lattice_data[128 + top_k + p * top_k + 1] = -0.1f;
    }

    // Position 2 (last): candidate ids [0, 1].
    //   From pred 0: scores [0, 0]     (weak, tied)
    //   From pred 1: scores [10, -10]  (near-certain)
    lattice_data[256] = 0.0f;
    lattice_data[257] = 1.0f;
    lattice_data[256 + top_k + 0 * top_k + 0] = 0.0f;
    lattice_data[256 + top_k + 0 * top_k + 1] = 0.0f;
    lattice_data[256 + top_k + 1 * top_k + 0] = 10.0f;
    lattice_data[256 + top_k + 1 * top_k + 1] = -10.0f;

    common_dflash2_lattice lat{
        lattice_data.data(),
        128,
        n_pos,
        top_k
    };

    common_dflash2_walk walk_dp;
    common_dflash2_walk_lattice(lat, true, walk_dp);

    common_dflash2_walk walk_greedy;
    common_dflash2_walk_lattice(lat, false, walk_greedy);

    // Greedy must take the locally-best candidate 0 at position 1, then candidate 0 at position 2
    // (tie, first maximum). DP must take candidate 1 at position 1, then candidate 0 at position 2.
    DF2_CHECK(walk_greedy.idx.size() == 2 && walk_greedy.idx[0] == 0 && walk_greedy.idx[1] == 0);
    DF2_CHECK(walk_dp.idx.size() == 2 && walk_dp.idx[0] == 1 && walk_dp.idx[1] == 0);

    float dp_E_L     = compute_expected_length(lattice_data, top_k, 128, walk_dp.idx);
    float greedy_E_L = compute_expected_length(lattice_data, top_k, 128, walk_greedy.idx);

    DF2_CHECK(dp_E_L > greedy_E_L + 1e-4f && "DP must strictly beat greedy on this lattice");
    // Independently-derived constants, computed outside the implementation under test.
    DF2_CHECK(std::fabs(greedy_E_L - 0.824751f) < 1e-4f && "greedy E[L] does not match hand derivation");
    DF2_CHECK(std::fabs(dp_E_L - 0.900332f) < 1e-4f && "DP E[L] does not match hand derivation");

    std::cout << "  PASS: DP strictly beats greedy on hand-written lattice (E[L] " << dp_E_L
              << " vs " << greedy_E_L << ")" << std::endl;
}

// Test: Determinism
static void test_determinism() {
    std::cout << "Test: Determinism..." << std::endl;

    std::mt19937 rng(789);
    std::uniform_real_distribution<float> dist(-2.0f, 2.0f);

    for (int test_idx = 0; test_idx < 100; ++test_idx) {
        int top_k = 2 + rng() % 8;
        int n_pos = 2 + rng() % 6;

        std::vector<float> lattice_data(n_pos * 128);
        for (size_t i = 0; i < lattice_data.size(); ++i) {
            lattice_data[i] = dist(rng);
        }

        common_dflash2_lattice lat{
            lattice_data.data(),
            128,
            (int32_t)n_pos,
            (int32_t)top_k
        };

        common_dflash2_walk walk1;
        common_dflash2_walk_lattice(lat, false, walk1);
        common_dflash2_walk_lattice(lat, true, walk1);

        common_dflash2_walk walk2;
        common_dflash2_walk_lattice(lat, false, walk2);
        common_dflash2_walk_lattice(lat, true, walk2);

        DF2_CHECK(walk1.idx == walk2.idx && "Determinism failed for idx");
        DF2_CHECK(walk1.p == walk2.p && "Determinism failed for p");
        DF2_CHECK(walk1.work == walk2.work && "Determinism failed for work");

        // Also check reuse of walk struct
        common_dflash2_walk walk3;
        for (int i = 0; i < 5; ++i) {
            common_dflash2_walk_lattice(lat, true, walk3);
        }
        DF2_CHECK(walk1.idx == walk3.idx && "Reuse did not give same result");
    }

    std::cout << "  PASS: Deterministic over 100 random lattices and repeated calls" << std::endl;
}

// Test: Degenerate input safety
static void test_degenerate_safety() {
    std::cout << "Test: Degenerate input safety..." << std::endl;

    std::vector<float> lattice_data(10 * 128);
    std::fill(lattice_data.begin(), lattice_data.end(), 1.0f);

    common_dflash2_walk walk;

    // n_pos < 2
    common_dflash2_lattice lat1{lattice_data.data(), 128, 1, 4};
    common_dflash2_walk_lattice(lat1, false, walk);
    DF2_CHECK(walk.idx.empty() && "n_pos < 2 should yield empty idx");
    common_dflash2_walk_lattice(lat1, true, walk);
    DF2_CHECK(walk.idx.empty() && "n_pos < 2 DP should yield empty idx");

    // top_k < 1
    common_dflash2_lattice lat2{lattice_data.data(), 128, 5, 0};
    common_dflash2_walk_lattice(lat2, false, walk);
    DF2_CHECK(walk.idx.empty() && "top_k < 1 should yield empty idx");
    common_dflash2_walk_lattice(lat2, true, walk);
    DF2_CHECK(walk.idx.empty() && "top_k < 1 DP should yield empty idx");

    // nullptr data
    common_dflash2_lattice lat3{nullptr, 128, 5, 4};
    common_dflash2_walk_lattice(lat3, false, walk);
    DF2_CHECK(walk.idx.empty() && "nullptr should yield empty idx");
    common_dflash2_walk_lattice(lat3, true, walk);
    DF2_CHECK(walk.idx.empty() && "nullptr DP should yield empty idx");

    // Non-finite scores
    lattice_data.clear();
    lattice_data.resize(2 * 128);
    std::fill(lattice_data.begin(), lattice_data.end(), 0.0f);
    // Position 0: dummy
    lattice_data[0] = 0.0f;
    lattice_data[1] = 1.0f;
    // Position 1: valid candidate ids, then scores with NaN
    lattice_data[128] = 0.0f;
    lattice_data[129] = 1.0f;
    lattice_data[130] = std::numeric_limits<float>::quiet_NaN(); // Transition score with NaN
    lattice_data[131] = 1.0f;

    common_dflash2_lattice lat4{lattice_data.data(), 128, 2, 2};
    common_dflash2_walk_lattice(lat4, false, walk);
    DF2_CHECK(walk.idx.empty() && "Non-finite score should truncate draft");
    common_dflash2_walk_lattice(lat4, true, walk);
    DF2_CHECK(walk.idx.empty() && "Non-finite score DP should truncate draft");

    std::cout << "  PASS: Degenerate inputs handled safely" << std::endl;
}

// Test: Allocation-free after warmup
static void test_allocation_free() {
    std::cout << "Test: Allocation-free after warmup..." << std::endl;

    std::mt19937 rng(101);
    std::uniform_real_distribution<float> dist(-2.0f, 2.0f);

    int top_k = 10;
    int n_pos = 8;

    std::vector<float> lattice_data(n_pos * 128);
    for (size_t i = 0; i < lattice_data.size(); ++i) {
        lattice_data[i] = dist(rng);
    }

    common_dflash2_lattice lat{
        lattice_data.data(),
        128,
        (int32_t)n_pos,
        (int32_t)top_k
    };

    common_dflash2_walk walk;

    // Warmup call
    common_dflash2_walk_lattice(lat, true, walk);
    size_t idx_cap = walk.idx.capacity();
    size_t p_cap = walk.p.capacity();
    size_t work_cap = walk.work.capacity();

    // 10000 reuse calls
    for (int i = 0; i < 10000; ++i) {
        common_dflash2_walk_lattice(lat, true, walk);
        DF2_CHECK(walk.idx.capacity() == idx_cap && "idx capacity changed");
        DF2_CHECK(walk.p.capacity() == p_cap && "p capacity changed");
        DF2_CHECK(walk.work.capacity() == work_cap && "work capacity changed");
    }

    std::cout << "  PASS: Zero allocations over 10000 reuse calls" << std::endl;
}

// Test: Position-1 canary
static void test_pos1_canary() {
    std::cout << "Test: Position-1 canary..." << std::endl;

    // Create a valid lattice where the invariant holds
    std::vector<float> lattice_data(2 * 128);
    std::fill(lattice_data.begin(), lattice_data.end(), 0.0f);

    int top_k = 4;
    // Position 0: dummy
    for (int i = 0; i < top_k; ++i) {
        lattice_data[i] = (float)i;
    }

    // Position 1: candidates and scores where row_1[top_k + 0*top_k + c] == row_1[top_k + 1*top_k + c]
    // This happens when ggml_repeat_4d makes them uniform (n_pred == 1)
    for (int i = 0; i < top_k; ++i) {
        lattice_data[128 + i] = (float)i;
    }
    for (int c = 0; c < top_k; ++c) {
        lattice_data[128 + top_k + c] = 1.5f + c * 0.1f;
        lattice_data[128 + top_k + top_k + c] = 1.5f + c * 0.1f; // Same as above
    }

    common_dflash2_lattice lat_valid{
        lattice_data.data(),
        128,
        2,
        (int32_t)top_k
    };

    DF2_CHECK(common_dflash2_check_pos1_canary(lat_valid) && "Valid lattice should pass canary");

    // Now violate the invariant: make row_1[top_k + 0*top_k + c] != row_1[top_k + 1*top_k + c]
    lattice_data[128 + top_k + 1] = 2.5f; // Violate at c=1
    DF2_CHECK(!common_dflash2_check_pos1_canary(lat_valid) && "Violated lattice should fail canary");

    std::cout << "  PASS: Position-1 canary detects invariant violations" << std::endl;
}

// Test: Adversarial calibration-skew
static void test_calibration_skew() {
    std::cout << "Test: Adversarial calibration-skew (OQ-1 probe)..." << std::endl;

    // Create a lattice where position 1 captures most mass and position 2 captures little
    // DP should still not do worse than greedy because it maximizes the right objective
    std::vector<float> lattice_data(3 * 128);
    std::fill(lattice_data.begin(), lattice_data.end(), 0.0f);

    int top_k = 3;

    // Position 0: dummy
    for (int i = 0; i < top_k; ++i) {
        lattice_data[i] = (float)i;
    }

    // Position 1: strong scores (high mass capture)
    for (int i = 0; i < top_k; ++i) {
        lattice_data[128 + i] = (float)i;
    }
    lattice_data[128 + top_k + 0] = 3.0f;  // High score
    lattice_data[128 + top_k + 1] = -5.0f; // Very low
    lattice_data[128 + top_k + 2] = -5.0f; // Very low
    // Softmax: ~0.99, ~0.005, ~0.005

    // Position 2: weak scores (low mass capture)
    // Careful: this is conditioned on position 1's choice
    for (int i = 0; i < top_k; ++i) {
        lattice_data[256 + i] = (float)i;
    }
    // From pred 0 (likely choice at pos 1):
    lattice_data[256 + top_k + 0] = 0.5f;   // Weak
    lattice_data[256 + top_k + 1] = 0.4f;   // Weak
    lattice_data[256 + top_k + 2] = 0.3f;   // Weak
    // From pred 1 (unlikely):
    lattice_data[256 + top_k + top_k + 0] = 2.0f;
    lattice_data[256 + top_k + top_k + 1] = 0.0f;
    lattice_data[256 + top_k + top_k + 2] = 0.0f;
    // From pred 2 (unlikely):
    lattice_data[256 + top_k + 2*top_k + 0] = 2.0f;
    lattice_data[256 + top_k + 2*top_k + 1] = 0.0f;
    lattice_data[256 + top_k + 2*top_k + 2] = 0.0f;

    common_dflash2_lattice lat{
        lattice_data.data(),
        128,
        3,
        (int32_t)top_k
    };

    common_dflash2_walk walk_dp;
    common_dflash2_walk_lattice(lat, true, walk_dp);

    common_dflash2_walk walk_greedy;
    common_dflash2_walk_lattice(lat, false, walk_greedy);

    auto compute_E_L = [&](const std::vector<int32_t> & path) {
        float prob_prefix = 1.0f;
        float E_L = 0.0f;
        for (size_t i = 0; i < path.size(); ++i) {
            int pos = i + 1;
            int pred = (i == 0) ? 0 : path[i - 1];
            int cand = path[i];
            const float * row = lattice_data.data() + pos * 128;
            const float * scores = row + top_k + (size_t)pred * top_k;

            float s_max = scores[0];
            for (int k = 1; k < top_k; ++k) {
                if (scores[k] > s_max) s_max = scores[k];
            }
            float sum = 0.0f;
            for (int k = 0; k < top_k; ++k) {
                sum += std::exp(scores[k] - s_max);
            }
            float prob_c = std::exp(scores[cand] - s_max) / sum;

            prob_prefix *= prob_c;
            E_L += prob_prefix;
        }
        return E_L;
    };

    float dp_E_L = compute_E_L(walk_dp.idx);
    float greedy_E_L = compute_E_L(walk_greedy.idx);

    DF2_CHECK(dp_E_L >= greedy_E_L - 1e-6f && "DP should not do worse than greedy under E[L]");

    std::cout << "  PASS: DP never scores worse than greedy (E[L] DP=" << dp_E_L
              << " vs greedy=" << greedy_E_L << ")" << std::endl;
}

// Test: timing bound at n_pos=8, top_k=10.
// The design's cost gate (section 6.5 / P803 criterion 11) is stated for the GX10 aarch64 CPU.
// This test runs on whatever host builds this binary, which is informational evidence only -
// it does not substitute for a GX10 measurement. The multiply-add bound (n_pos*top_k*top_k) and
// the backward-pass expf count (also n_pos*top_k*top_k, not n_pos*top_k - see the comment on
// dp_walk() in speculative-dflash2.cpp) are structural properties of the loop nests and are
// verified by inspection, not by runtime instrumentation.
static void test_timing_bound() {
    std::cout << "Test: timing bound (informational - host CPU, not GX10 aarch64)..." << std::endl;

    std::mt19937 rng(202);
    std::uniform_real_distribution<float> dist(-2.0f, 2.0f);

    const int top_k = 10;
    const int n_pos = 8;

    std::vector<float> lattice_data(n_pos * 128);
    for (auto & v : lattice_data) {
        v = dist(rng);
    }

    common_dflash2_lattice lat{lattice_data.data(), 128, n_pos, top_k};
    common_dflash2_walk walk;

    // Warm up (also exercises the allocation path once, before timing).
    for (int i = 0; i < 100; ++i) {
        common_dflash2_walk_lattice(lat, true, walk);
    }

    const int reps = 5000;
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < reps; ++i) {
        common_dflash2_walk_lattice(lat, true, walk);
    }
    auto t1 = std::chrono::steady_clock::now();

    double us_per_call = std::chrono::duration<double, std::micro>(t1 - t0).count() / reps;
    std::cout << "  measured " << us_per_call << " us/call on this host" << std::endl;

    DF2_CHECK(us_per_call < 20.0 && "DP walk exceeded the 20us budget on this host");

    std::cout << "  PASS: under 20us/call on this host (GX10 aarch64 measurement still required)" << std::endl;
}

int main() {
    std::cout << "Running DFlash2 walk unit tests..." << std::endl;
    std::cout << std::endl;

    test_greedy_equivalence();
    test_top_k_one();
    test_last_position_agreement();
    test_dp_optimality();
    test_dp_beats_greedy();
    test_determinism();
    test_degenerate_safety();
    test_allocation_free();
    test_pos1_canary();
    test_calibration_skew();
    test_timing_bound();

    std::cout << std::endl;
    std::cout << "All tests passed!" << std::endl;

    return 0;
}
