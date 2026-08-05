IMPORTANT: Ensure you’ve thoroughly reviewed the [AGENTS.md](AGENTS.md) file before beginning any work.

# Fork context

This is a **private fork** (`swiru95/llama.cpp`) of `ggml-org/llama.cpp`. The goal of the fork is the auth work described in [PLAN.md](PLAN.md): RBAC (admin/user), OIDC, and mTLS in `llama-server`. Per AGENTS.md, private forks are exempt from the upstream contribution restrictions - but if any change is ever proposed upstream, the full AGENTS.md rules apply (no AI-written PR descriptions, no automated submissions, human must own and understand every line).

Upstream code-style rules from AGENTS.md still apply to all code written here (ASCII only - no em-dashes or unicode arrows, concise comments, blend in with surrounding code, reuse existing infrastructure).

# Source of truth

- [PLAN.md](PLAN.md) - the full implementation plan. Read the relevant section before touching any auth code.
- [features.json](features.json) - the feature backlog. Every unit of work is a feature entry. Do not start work that has no feature entry; do not mark a feature `done` unless its acceptance criteria and tests pass.
- The plan's line numbers are approximate and rot quickly - `tools/server/` is refactored aggressively upstream. Always re-verify anchors (`grep` for `middleware_validate_api_key`, `pre_routing_handler`, etc.) before editing.

# Development workflow (multi-agent, model-tiered)

Work is split across specialized agents defined in `.claude/agents/`. Respect the tiering - it is a deliberate cost/quality tradeoff:

| Stage | Agent | Model | Responsibility |
|---|---|---|---|
| 1. Design | `architect` | Opus | High-level design, interface contracts, feature breakdown into features.json |
| 2. Challenge | `challenger` | Fable | Adversarial review of designs and plans: attack-surface analysis, edge cases, simplifications, "what breaks on rebase" |
| 3. Implement | `coder` | Haiku | Write the code for one feature at a time, exactly per the approved design |
| 4. Verify | `reviewer` | Sonnet | Review the coder's diff, verify it matches the design and acceptance criteria, fix defects directly |
| 5. Test plan | `test-planner` | Sonnet | Turn acceptance criteria into concrete test cases (negative cases first) |
| 6. Test run | `test-runner` | Haiku | Execute builds and test suites, report results verbatim, update features.json status |

Loop per feature: architect designs (once per PR-stage, not per feature) -> challenger attacks the design -> coder implements -> reviewer verifies and corrects -> test-planner defines tests -> test-runner executes -> reviewer signs off -> feature `done` in features.json. The challenger may be re-engaged at any point when a design assumption turns out false.

Rules for the orchestrating (top-level) session:
- Dispatch implementation work to `coder`, never write feature code directly in the top-level session unless the change is trivial (< ~10 lines).
- Never let `coder` mark its own work as verified. Verification status changes in features.json come from `reviewer` or `test-runner` results only.
- One feature in `in_progress` per agent at a time. Update features.json status transitions immediately (`todo -> in_design -> in_progress -> in_review -> testing -> done`, `blocked` from anywhere with a `blocked_reason`).
- Security-sensitive code (path normalization, JWT validation, mTLS identity extraction, policy decisions) always goes through `challenger` review in addition to `reviewer`.

## Compaction checkpoint (after each feature)

When a feature reaches `done`, compact the orchestrating session before starting the next one. This is safe here because the durable state lives outside the conversation - features.json (status, acceptance criteria, test_refs), the design docs under docs/design/, and the code itself - and every subagent starts from a cold context regardless. The orchestrator conversation is only a dispatcher, so nothing load-bearing is lost.

Before compacting, make sure everything needed to resume is persisted, not just in the transcript:
- the finished feature's status and test-run summary are written to features.json,
- any design change discovered mid-implementation is folded back into its docs/design/ doc (not left as a chat note),
- unresolved findings are captured as a `blocked`/`todo` feature with a `blocked_reason`, not carried in your head.

After that, a fresh context can pick up the next feature from features.json alone. Keep a one-line pointer to "next feature id" in your handoff so the resumed session knows where to start. Do not compact mid-feature (design not yet folded back, or a diff in flight) - only at a `done` boundary.

# Build and test

```sh
# configure + build the server target
cmake -B build -DLLAMA_BUILD_SERVER=ON
cmake --build build --target llama-server -j

# server test suite (pytest)
cd tools/server/tests
./tests.sh                 # all tests
./tests.sh unit/test_authz.py -v   # single file
```

Server tests need a small GGUF model; `utils.py::ServerProcess` handles download/caching. New CLI flags must be threaded through `tools/server/tests/utils.py::ServerProcess` to be testable.

# Hard rules for the auth work

- **Fail closed.** Auth init failure = server refuses to start. Unknown route = deny. Unmapped role/claim = deny. Never a default role.
- **Deny-by-default route table.** Every registered route must have an entry in the route->permission table; a startup assertion enforces this. When rebasing onto upstream, new upstream endpoints must fail the assertion, not silently become public.
- **Path normalization before any policy match.** Tests for `/Slots`, `//slots`, `/slots/`, `%2e%2e`, `%00` exist and must keep passing.
- **No secrets in argv.** Secrets come from files or env only. Never log tokens, `Authorization` headers, prompts, or full DNs.
- **Minimize footprint in existing files.** All auth logic lives in new files (`server-auth.*`, `server-oidc.*`, `server-mtls.*`); existing files get call sites only. This keeps the perpetual rebase cheap.
- **No hand-rolled crypto.** JWT via jwt-cpp; comparisons via `CRYPTO_memcmp` on hashes.
- Never commit, push, or open PRs without explicit human approval for each action.
