# PR6 - General `--config <file.yaml>` loader (F012)

Status: design (in_design). Feature: F012 (umbrella) -> F012a, F012b, F012c.

## 0. Scope and relation to PLAN.md

PLAN.md sections 1-10 describe the auth work (PR1-PR5) and do NOT mention a YAML
config loader. PR6/F012 is a user-requested extension recorded in features.json,
not in PLAN.md's rollout table (section 5, which stops at PR5). There are
therefore no PLAN.md line anchors to verify for this stage; all anchors below are
in `common/arg.cpp` and `common/common.h` and were verified against the current
tree.

Goal: a general `--config <file.yaml>` that maps YAML keys to the EXISTING
llama-server arg setters (any documented option, not auth-only), and can also
carry the RBAC policy in YAML. No hand-rolled YAML parser: use the vendored,
header-only fkYAML library (MIT). The design translates YAML into the SAME code
path CLI/env already use, so every current and future flag works with zero
per-flag code and cannot drift on rebase.

## 1. Dependency: vendor fkYAML (OQ1)

- Library: fkYAML, single-header, MIT, C++11+ (llama.cpp is C++17). Header-only,
  no build system, no link step - the simplest possible vendoring, matching the
  precedent of `vendor/nlohmann/`.
- Pinned version: fkYAML v0.4.2 (single-header distribution
  `single_include/fkYAML/node.hpp`). The exact tag is OQ1 for the challenger to
  confirm/bump; pin to a specific released tag, never a moving branch.
- Path: `vendor/fkYAML/node.hpp` plus `vendor/fkYAML/LICENSE`. This sits next to
  `vendor/nlohmann/` at repo root.
- CMake wiring: NONE required beyond adding the new source file. The `common`
  static library already has `../vendor` as a PUBLIC include directory
  (`common/CMakeLists.txt:129`, the same line that lets `arg.cpp` resolve
  `<nlohmann/json.hpp>`). So `#include <fkYAML/node.hpp>` resolves to
  `vendor/fkYAML/node.hpp` with no new `target_include_directories`. The only
  CMake change is adding `config.cpp` to the `common` `add_library` source list
  (`common/CMakeLists.txt:56`).
- Justification vs rapidyaml: rapidyaml is faster but ships as a compiled library
  (`.cpp` + its own `c4core` dependency), needs a build target and an arena API.
  fkYAML is a single header with an nlohmann-like node API and built-in typed
  accessors - dramatically less integration surface for a config loader that runs
  once at startup where parse speed is irrelevant. fkYAML is the right tradeoff.

## 1a. Existing config-file loader `common_preset` - build on it, do not duplicate

CONTRADICTION-WITH-CODEBASE FINDING (not in the original draft): the codebase
ALREADY has a config-FILE loader over the same `common_arg` registry -
`common/preset.{h,cpp}`. Verified pieces:

- `parse_ini_from_file` (`preset.cpp:170`) parses an INI file via a PEG grammar
  into `section -> {key: value}`.
- `get_map_key_opt` (`preset.cpp:251`) maps each flag's env name and its
  dash-stripped arg names (`rm_leading_dashes`, `preset.cpp:12`) to its
  `common_arg`.
- `load_from_ini` (`preset.cpp:285`) rejects an UNKNOWN key with a throw
  (`preset.cpp:326`, fail closed) and negation-normalizes bool args via
  `parse_bool_arg` (`preset.cpp:268`).
- `common_preset::to_args` (`preset.cpp:37`) renders the collected
  `map<common_arg,string>` back into a CLI token vector; `apply_to_params`
  (`preset.cpp:142`) applies handlers directly. There is even a
  `filter_allowed_keys` allowlist for remote presets (`preset.h:59`).

Implication: PR6 must NOT invent a parallel setter table. But the preset loader
is INI-only and its PEG grammar cannot represent the nested `auth_policy`
structure PR6 needs, so we CANNOT reuse `parse_ini_from_file`. We reuse the layer
that matters - the shared `common_arg` registry + handler dispatch (section 2) -
and we deliberately mirror preset's proven semantics (dash/underscore key
normalization, unknown-key = hard fail, bool negation, token synthesis) so the
YAML path behaves consistently with the INI path. PR6 becomes a third sibling
consumer of the registry alongside CLI and preset, never a reimplementation of
the flag switch. Whether to instead share one token-rendering helper with
`common_preset::to_args` is OQ0 for the challenger.

## 2. The arg-infrastructure injection point (verified)

Entry: `common_params_parse` (`common/arg.cpp:1203`) ->
`common_params_parse_ex(argc, argv, ctx_arg)` (`common/arg.cpp:691`). Inside
`common_params_parse_ex` the relevant, verified anchors are:

- `common/arg.cpp:697-705` - the arg registry is flattened into
  `std::unordered_map<std::string, std::pair<common_arg*, bool>> arg_to_options`,
  keyed by every flag string (positive and negated `args_neg`).
- `common/arg.cpp:708-730` - the ENV pass: for each `common_arg`,
  `get_value_from_env()` and the matching handler is invoked
  (`handler_void`/`handler_int`/`handler_bool`/`handler_string`).
- `common/arg.cpp:739-812` - `parse_cli_args()` lambda: loops over `argv`,
  normalizes `_`->`-` for `--` tokens (`arg.cpp:747`), rejects unknown flags
  (`arg.cpp:749-751`), then dispatches by handler type: `handler_void` (no value),
  `handler_bool` (no value, `is_positive` from positive-vs-negated match),
  `handler_int`/`handler_string` (one value), `handler_str_str` (two values).
- `common/arg.cpp:815` - `parse_cli_args()` is invoked.

Effective existing precedence: ENV applied first (708-730), then CLI (815); CLI
handlers overwrite scalar params set by ENV, so today the model is
**CLI > env > defaults**.

The `common_arg` contract (`common/arg.h:21-108`) has exactly one handler set per
flag: `handler_void`, `handler_string`, `handler_str_str`, `handler_int`, or
`handler_bool`, plus `args`, `args_neg`, `env`, `value_hint`, `value_hint_2`.
`add_opt` (`arg.cpp:1354-1360`) registers COMMON flags plus the current example's
flags, so for `ex == LLAMA_EXAMPLE_SERVER` the registry contains every server and
common flag; a config key naming a flag not registered for this binary is a true
unknown (correct fail-closed behavior).

**Injection: between line 705 and line 708** - after `arg_to_options` is built and
BEFORE the ENV pass. Applying config there yields the target precedence
**CLI > env > config-file > defaults**: config is the lowest override layer above
compiled defaults; ENV overwrites it; CLI overwrites both.

To reuse the exact dispatch (zero drift), refactor the token-processing core of
`parse_cli_args()` into a shared lambda:

```cpp
// arg.cpp, inside common_params_parse_ex, after arg_to_options is built
auto apply_tokens = [&](const std::vector<std::string> & toks, bool is_cli) {
    // exact body of the current parse_cli_args inner loop (arg.cpp:742-800),
    // reading toks[i] instead of argv[i], toks.size() instead of argc.
};
```

`parse_cli_args()` becomes `apply_tokens(argv_as_vector, /*is_cli=*/true)` (the
mmap/load-mode deprecation check at `arg.cpp:802-811` stays in the CLI wrapper).
Config is applied as the lowest layer with `apply_tokens(cfg_tokens, false)`. This
is the whole point of the "YAML -> CLI tokens" bridge: config values flow through
the identical handler switch as CLI and ENV, so any flag - present or future -
works for free and cannot silently break on rebase.

**S4 - two warnings MUST be gated on `is_cli`.** The current inner loop emits two
diagnostics that are wrong for the config-apply pass (which runs BEFORE the ENV
pass, i.e. below env in precedence):

- the duplicate-argument deprecation warning (`arg.cpp:752-758`), and
- the env-overwrite warning `"%s environment variable is set, but will be
  overwritten by command line argument %s"` (`arg.cpp:762-764`), which fires
  whenever `opt.has_value_from_env()`.

During the config pass the env-overwrite message is both a misfire and BACKWARDS
(env actually overwrites config here, per precedence). Both `if` blocks must be
guarded by `is_cli` so neither fires while applying config tokens. This gating is
part of the `apply_tokens` extraction, not a separate change.

Config path resolution (highest to lowest for the PATH itself): scan `argv` ONLY
for `--config` (applying the same `_`->`-` normalization to `--` tokens) and take
the following token, last occurrence wins; else `getenv("LLAMA_ARG_CONFIG")`.
`--config` has NO short alias (S2: `-C` is `--cpu-mask` at `arg.cpp:1457`, `-c`
is `--ctx-size` at `arg.cpp:1559`; neither may be repurposed). A trailing
`--config` with no value is left for `parse_cli_args()` to report
("expected value").

## 3. Flag

```
--config PATH        (env LLAMA_ARG_CONFIG)
```

- No short alias. NOTE: `-C` is already taken by `--cpu-mask` (`arg.cpp:1457`);
  do NOT reuse it (the earlier draft's `--config, -C` was wrong). `--config` has
  no short form.
- Registered as a COMMON flag (default `LLAMA_EXAMPLE_COMMON`, available to every
  binary), near the other early common flags. `set_env("LLAMA_ARG_CONFIG")`.
- Handler is a plain `handler_string` that stores the path into
  `common_params::config_file` (new field). The actual file load happens at the
  injection point (section 2), not in the handler - the handler exists only so
  `parse_cli_args()` does not reject `--config` as unknown and so `--config`
  round-trips into params/usage like every other flag.
- The path is resolved and the file loaded ONCE (pre-scan), so setting both
  `--config` and `LLAMA_ARG_CONFIG` does not double-load.

## 4. Mapping model: YAML -> synthetic CLI tokens

New helper in a small new translation unit `common/config.{h,cpp}` (part of the
`common` lib, so it inherits the `../vendor` include and can see `common_arg`):

```cpp
// common/config.h
#pragma once
#include "arg.h"
#include <functional>
#include <string>
#include <vector>

// Translate a YAML config file into a flat list of CLI-equivalent tokens
// (e.g. {"--ctx-size","4096","--api-key","k1,k2"}). Throws std::runtime_error
// with a clear, single-line message on any failure (malformed YAML, non-mapping
// root, unknown key, bad value shape) so the caller aborts startup (fail closed).
// `lookup` returns the registered common_arg for a flag string, or nullptr.
std::vector<std::string> common_config_to_args(
    const std::string & path,
    const std::function<const common_arg *(const std::string &)> & lookup);
```

Call site in `arg.cpp` (injection point):

```cpp
std::string config_path = /* pre-scan argv, else env LLAMA_ARG_CONFIG */;
if (!config_path.empty()) {
    auto lookup = [&](const std::string & flag) -> const common_arg * {
        auto it = arg_to_options.find(flag);
        return it == arg_to_options.end() ? nullptr : it->second.first;
    };
    apply_tokens(common_config_to_args(config_path, lookup), /*warn_dups=*/false);
}
```

### 4.1 Key -> flag name

For each top-level mapping key `k`: `flag = "--" + k` with every `_` replaced by
`-`. So `ctx_size`, `ctx-size` both map to `--ctx-size` (mirrors the CLI's own
`_`->`-` normalization at `arg.cpp:747`). Then `lookup(flag)`:

- `nullptr` -> throw: `unknown config key '<k>' (maps to <flag>)`. HARD FAIL,
  server refuses to start. This is deliberate and is the rebase-safety property
  (section 6): a typo in a security setting, or a key mapping to an
  upstream-removed/renamed flag, aborts loudly instead of being silently ignored.
- key `config` / `c` -> throw `nested --config in a config file is not allowed`
  (prevents recursion).

### 4.2 Value shape -> tokens (branch on the matched handler)

The matched `common_arg` tells us how many tokens the flag consumes; the YAML node
type tells us the value. Rules (each is fully determined - no coder decision):

- `handler_void` (flag takes no value): YAML value MUST be a boolean.
  `true` -> emit `{flag}`; `false` -> emit nothing (mirrors the ENV rule
  `is_truthy` at `arg.cpp:712`). Any non-bool -> throw.
- `handler_bool` (negatable `--x`/`--no-x`): YAML value MUST be a boolean.
  `true` -> emit `{args[0]}`; `false` -> emit `{args_neg[0]}` (every
  `handler_bool` flag has `args_neg` by construction, `arg.h:61-66`). Non-bool ->
  throw.
- `handler_int` / `handler_string` (one value):
  - scalar -> emit `{flag, scalar_to_token(node)}`.
  - sequence of scalars -> emit `{flag, join(elems, ",")}` (comma-join). This
    matches the codebase's CSV convention (e.g. `--api-key` CSV-splits and
    appends, `arg.cpp:3349-3355`; `--oidc-audience`, `--auth-trusted-proxies`,
    `--oidc-algs` are all `STR[,STR...]`). See F012b.
  - mapping / other -> throw.
- `handler_str_str` (two values): YAML value MUST be a 2-element sequence ->
  emit `{flag, str(v0), str(v1)}`; any other shape -> throw. Repeatable str_str
  is unsupported (documented). See F012b. (No `handler_str_str` flag is currently
  in server scope, so this is an edge kept for completeness.)

`scalar_to_token(node)` rendering (deterministic):

- string  -> value verbatim (a quoted YAML scalar is a string node, passed
  through unchanged - use quotes when an exact literal is required),
- boolean -> `"true"` / `"false"`,
- integer -> `std::to_string(int64)`,
- float   -> serialized numeric text (note: `0.8` may render as `0.800000`;
  numerically equivalent for `stof/stod` handlers; document that operators
  needing an exact string should quote it),
- null    -> throw (a bare key with no value is almost always a mistake; fail
  closed).

### 4.3 Precedence and combining

- Layering: **CLI > env > config-file > defaults**. Config applied at the
  injection point (before the ENV pass), ENV overwrites, CLI overwrites.
- Scalar/overwrite handlers: last writer wins, so CLI beats env beats config.
- Append/CSV handlers (e.g. `--api-key`): the handler APPENDS, so a key set in
  both config and CLI COMBINES (both retained) rather than overrides. This is
  inherent to those handlers and is documented, not worked around.

## 5. Auth policy in YAML

Two mechanisms, both reusing the existing nlohmann-based policy parser in
`server_auth::init` - the schema is NEVER forked:

1. Baseline (free, no extra code): `--config` can set `--auth-policy-file` like any
   other key (`auth_policy_file: /etc/llama/policy.json`). Works via the generic
   bridge (section 4) with zero policy-specific code.
2. Inline policy (F012c, optional): a top-level `auth_policy:` mapping is
   recognized specially by `common_config_to_args` - it is NOT turned into a
   token. Its subtree is converted YAML->JSON via a small recursive
   `fkyaml_to_json(const fkyaml::node&) -> nlohmann::json` in `config.cpp`
   (structural mirror only: mapping/sequence/scalar) and stored as a JSON string
   in a new `common_params::auth_policy_inline`. `server_auth::init` parses that
   string with the SAME nlohmann code path it already uses for the file. If BOTH
   `auth_policy_inline` and `--auth-policy-file` are set -> startup error
   (ambiguous, fail closed).

This keeps a single policy schema and a single policy parser; YAML is only a
transport for the identical JSON structure.

## 6. Fail-closed and rebase safety (the key property)

- Malformed YAML -> `fkYAML` throws -> `common_config_to_args` rethrows a clear
  single-line message -> `common_params_parse_ex` propagates -> server refuses to
  start.
- Non-mapping document root -> throw.
- Unknown key (typo, or a key mapping to a flag upstream removed/renamed after a
  rebase) -> throw listing the key and derived flag -> refuse to start. Because
  config keys resolve against the LIVE `arg_to_options` registry, a rebase that
  drops or renames a flag turns a previously valid config into a loud startup
  failure instead of a silent behavior change. This is the same "fail on drift"
  guarantee the route->permission startup assertion gives the auth work.
- Bad value shape (list for a bool flag, scalar for str_str, null scalar, non-bool
  for a void/bool flag) -> throw.
- Inline `auth_policy` conflicting with `--auth-policy-file` -> throw.

Secrets: a config FILE may legitimately contain paths and (at the operator's
risk) tokens/keys - the "no secrets in argv" rule targets `ps`/argv exposure and
does not apply to a file the operator controls. Document: recommend `0600`
permissions on any config carrying secrets; llama-server never logs config
contents. Prefer `*_file` keys (e.g. `oidc_client_secret_file`) over inline
secrets.

## 7. New signatures / fields (summary)

- `common/common.h`: `std::string config_file = "";` and (F012c)
  `std::string auth_policy_inline = "";`.
- `common/config.h`: `common_config_to_args(path, lookup)` (section 4); (F012c)
  `nlohmann::json fkyaml_to_json(const fkyaml::node &)` (internal to config.cpp).
- `common/arg.cpp`: `--config` flag def; `resolve_config_path(argc, argv)` helper;
  `apply_tokens(tokens, warn_dups)` refactor of the `parse_cli_args` core; the
  injection call between lines 705 and 708.
- `tools/server/tests/utils.py`: `ServerProcess.config_file` threaded into
  `server_args` (mirroring `auth_policy_file`).
- (F012c) `tools/server/server-auth.cpp`: `server_auth::init` prefers
  `auth_policy_inline` when set; errors if both inline and file are set.

## 8. Test strategy (for the test-planner)

Negative first:

- malformed YAML (`: :`) -> startup abort, clear message.
- unknown key (`ctx_sizze: 4096`) -> startup abort naming the key and `--ctx-sizze`.
- non-mapping root (a top-level YAML list) -> startup abort.
- nested `config:` key -> startup abort.
- null scalar (`port:`) -> startup abort; list value on a bool flag -> abort.
- `auth_policy` inline AND `--auth-policy-file` both set -> abort (F012c).

Positive / precedence:

- YAML setting several ordinary flags (`port`, `ctx_size`, and one auth flag)
  makes the server behave exactly as if they were on the CLI.
- YAML list -> repeatable/CSV flag: `api_key: [k1, k2]` yields both keys usable.
- CLI overrides the same key set in config (`--port` on CLI wins over `port:` in
  config); `LLAMA_ARG_*` env overrides config; document the append exception for
  `--api-key`.
- `--config` supplied via `LLAMA_ARG_CONFIG` env has the same effect as on CLI.
- inline `auth_policy:` in YAML enforces RBAC: an admin-role principal reaches an
  ADMIN_STATE route, a user-role principal gets 403 there (F012c).

`ServerProcess` needs a `config_file` field; tests write a temp YAML and pass it.

## 9. Open questions for the challenger

- OQ0 (NEW, highest priority): `common_preset` (`common/preset.cpp`) is an
  existing INI config-file loader over the same `common_arg` registry, with
  unknown-key hard-fail, bool negation, and `to_args()` token synthesis (section
  1a). This design reuses the shared registry + handler dispatch but NOT preset's
  PEG INI parser (it cannot express the nested `auth_policy` YAML needs). Confirm
  PR6 should be a sibling YAML loader rather than (a) an INI-only extension of
  presets, or (b) a refactor sharing one token-rendering helper with
  `common_preset::to_args`. Option (b) improves reuse but couples PR6 to preset
  quirks (value_hint-driven value detection, preset-only skipping).
- OQ1: fkYAML vs rapidyaml, and the exact pinned tag (v0.4.2 proposed).
- OQ2: YAML -> CLI-token bridge (chosen) vs a direct YAML -> setter map. The
  bridge reuses the live handler switch (no per-flag code, no drift); a direct map
  would duplicate flag knowledge. Confirm the bridge is preferred.
- OQ3: unknown-key HARD FAIL (chosen) vs warn-and-ignore. Hard fail is consistent
  with the auth work's fail-closed ethos and catches security-setting typos.
- OQ4: inline `auth_policy` (F012c) yes/no, or ship only `auth_policy_file` via the
  generic bridge. F012c is optional and can be deferred.
- OQ5: precedence CLI > env > config-file > defaults (chosen, matches the existing
  env-then-CLI model). Confirm config below env is acceptable, or argue for
  config above env.
- OQ6: comma-join for YAML sequences (chosen, matches the CSV convention) vs
  emitting the flag repeatedly. Repeat breaks overwrite-CSV handlers
  (`oidc_audience`); comma-join breaks a genuinely repeatable non-CSV flag (none
  known in server scope). Confirm comma-join.

## 10. Challenger revisions (BINDING - these override any conflicting text above)

Applied after the Opus design-challenge. Where sections 1-9 conflict, THIS section wins.

### S1 (OQ0) - reuse `common_preset::to_args`, do NOT ship a parallel renderer
The YAML->tokens step MUST reuse the existing renderer, not re-derive token shape by
branching on handler type. Mechanism:
- Parse the YAML mapping. For each top-level key that is NOT `auth_policy`, populate a
  `common_preset` `options` entry: key -> the flag string (`--` + key with `_`->`-`),
  value -> the scalar string, or for a YAML sequence the comma-joined string (CSV
  convention). Booleans map to the preset's bool representation.
- Call `common_preset::to_args()` to render the flag tokens (it decides flag-vs-value via
  `value_hint` and negation via `is_falsey`/`args_neg`, the shipped/tested behavior).
- PR6 code handles ONLY the nested `auth_policy` subtree specially (S5); everything else
  goes through preset.
This deletes the section-4.2 handler-type switch (`handler_void`/`bool`/`int`/`string`/
`str_str`) as a PR6-owned renderer. Keep the injection-safe property: rendered value tokens
are single argv strings, never re-tokenized. `common_config_to_args` returns the vector
`to_args()` produced (plus nothing for auth_policy) for the caller's `apply_tokens`.

### S2 - `--config` has no short alias; recursion guard on `config` only
`resolve_config_path` pre-scans ONLY `--config` (and its `_`->`-` form) and env
`LLAMA_ARG_CONFIG`. No `-C` (that is `--cpu-mask`), no `-c` (that is `--ctx-size`). The
nested-config recursion guard rejects only a `config` key inside the file; do NOT guard `c`.

### S3 - fail-closed on hostile/ambiguous YAML shapes (refuse to start)
`common_config_to_args` MUST reject (throw -> startup abort) on each of:
- duplicate top-level keys (a second `api_key:` silently overriding the first is a security
  change) - reject rather than last-wins;
- YAML anchors/aliases and merge keys (`<<`) - reject, or bound alias-expansion so a
  billion-laughs document cannot exponentially expand and DoS startup;
- empty file / empty document;
- a multi-document stream (`---` separators): accept EXACTLY ONE document, else throw;
- non-mapping document root; a nested mapping value where a scalar/sequence is required;
  a null scalar for a value.
F012a acceptance MUST include: verify fkYAML's actual behavior on duplicate keys, alias/merge
expansion, and multi-document input BEFORE relying on it (the vendored parser's defaults are
not assumed). Add one negative test per shape.

### S4 - do not misfire the env-overwrite / dup warnings during config apply
The `apply_tokens(tokens, warn_dups)` extraction MUST gate BOTH the "seen arg" duplicate
warning AND the "environment variable is set, but will be overwritten by command line
argument" warning (arg.cpp ~762-764) on the is-CLI/`warn_dups` flag. During the config-apply
pass `warn_dups=false`, so neither warning fires (config runs before the ENV pass, and env
actually overwrites config, so the env warning would be both noisy and backwards).

### S5 - inline `auth_policy` (F012c): not free; preserve types; test weakening paths
F012c is KEPT but sequenced last (depends F012a+F012b). Requirements:
- `server_auth::init` currently gates ALL policy parsing on `if (has_policy_file)`
  (server-auth.cpp:626). F012c refactors this to load `policy` from EITHER
  `--auth-policy-file` OR `common_params::auth_policy_inline`; if BOTH are set -> startup
  abort (ambiguous, fail closed). This is real plumbing, not zero-code.
- `fkyaml_to_json` MUST preserve YAML 1.2 scalar TYPES: bool->JSON bool, int->JSON number,
  string->JSON string, so the strictly-typed parser works (e.g. `require_at_jwt_typ: true`
  must be a JSON bool, not the string "true", or `get<bool>()` throws and a valid policy
  fails to start).
- Tests (F012c): a bool policy field round-trips; an integer-looking permission value is
  REJECTED (parser requires string permission names); `roles: ~` (YAML null) fails closed
  rather than silently falling back to the compiled-in default admin/user roles
  (server-auth.cpp:689 `contains("roles") && is_object()`).
- Fallback (challenger C3): if F012c is descoped, `auth_policy_file:` via the generic bridge
  (S1) already delivers policy-in-config with zero new security surface.

### Confirmed correct (do NOT change)
Precedence CLI > env > config > defaults (config applied before the ENV pass). CSV/append
handlers (`--api-key`, `--oidc-audience`, `--auth-trusted-proxies`) COMBINE across
config+env+CLI (documented, inherent to append handlers). The value->single-token bridge is
injection-proof (values consumed via `argv[++i]` in the handler branch, never re-normalized).
Unknown-key HARD FAIL against the live `arg_to_options` registry = the rebase-drift guarantee.
