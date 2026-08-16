# systemd deployment (GX10 / any Linux box)

Installs the built `llama-server` under `/opt/llama-server`, configs under
`/etc/llama-server`, model cache and logs under `/var/lib/llama-server` and
`/var/log/llama-server`, running as a dedicated non-root `llama-server`
system account via systemd.

## Install

```sh
cmake --build build --target llama-server -j$(nproc)
sudo contrib/gx10-deploy/install.sh
```

The API key is generated automatically (printed once at the end of
install.sh, also saved at `/etc/llama-server/api.key`). Edit
`/etc/llama-server/models.ini` if you want different models than the
Qwen3-Coder / Qwen3-32B example, then:

```sh
sudo systemctl enable --now llama-server
sudo journalctl -u llama-server -f
```

## Upgrade

Rebuild, then re-run `install.sh` - it copies the new binaries but never
touches an existing `config.yaml` / `models.ini`, so your settings survive:

```sh
git pull
cmake --build build --target llama-server -j$(nproc)
sudo contrib/gx10-deploy/install.sh
sudo systemctl restart llama-server
```

## Files

- `install.sh` - the installer, safe to re-run.
- `llama-server.service` - systemd unit template (`@INSTALL_PREFIX@` is
  substituted by install.sh); hardened (`ProtectSystem=strict`,
  `NoNewPrivileges`, no extra capabilities, GPU device access only via
  group membership, not broad device access).
- `config.yaml.example`, `models.ini.example` - copied to `/etc/llama-server/`
  on first install only.

## IMPORTANT: what can and cannot go in config.yaml

`llama-server`'s router mode passes its own `--config` argument down to
every model instance it spawns, verbatim, and each instance re-parses that
file completely independently. Anything in `config.yaml` that identifies
the process as a *router* - `port`, `models-preset`, `models-max`,
`models-autoload`, `api-key` - will therefore also be picked up by every
spawned child, which will then *also* decide it's a router and spawn two
more children. Recursively. Unbounded. This is not hypothetical: it is
exactly what happens if you put those keys in `config.yaml`, confirmed by
running it.

Those five settings live directly on the `ExecStart` line in
`llama-server.service` instead (as CLI flags, which the router correctly
strips before rendering a child's arguments - only a re-read *file*
defeats that stripping). `config.yaml` is for settings that are fine, or
even desirable, to also apply identically to every spawned instance:
`auth-audit-log`, `auth_policy`, `oidc-*`, `mtls-*`. Do not add
`port`/`models-preset`/`models-max`/`models-autoload`/`api-key` to it.

## Troubleshooting: "GET failed (401): Invalid username or password"

This almost always means the `hf-repo` in `models.ini` **does not exist**, not
that a credential is missing. The Hugging Face API will not confirm or deny
the existence of a private repo to an anonymous caller, so a nonexistent,
misspelled, or gated repo returns 401 rather than 404. Check the repo before
suspecting tokens or systemd:

```sh
curl -o /dev/null -w '%{http_code}\n' \
  https://huggingface.co/api/models/<owner>/<repo>
```

200 means public and resolvable; 401 means nonexistent, misspelled, or gated.
Run it as your own user - if it 401s for you too, no service configuration
can fix it.

## Troubleshooting: 400 "exceeds the available context size" at half your ctx-size

Adding `parallel = N` to a `models.ini` section silently halves (or worse) the
context each request can use. This is the single most confusing failure mode of
this deployment, because the number in the 400 does not match the number in the
config:

```
request (140010 tokens) exceeds the available context size (65536 tokens)
```

on a section that plainly says `ctx-size = 131072`.

The cause is that `parallel` is *auto* by default, and auto is not just a slot
count. `common/arg.cpp` defaults `n_parallel = -1`, and the server expands that
in `tools/server/server.cpp`:

```c
if (params.n_parallel < 0) {
    params.n_parallel = 4;
    params.kv_unified = true;   // auto turns this on
}
```

With `kv_unified` on, `llama_context` gives every sequence the whole context
(`src/llama-context.cpp`):

```c
if (cparams.kv_unified) { cparams.n_ctx_seq = cparams.n_ctx; }
else                    { cparams.n_ctx_seq = cparams.n_ctx / cparams.n_seq_max; }
```

Setting `parallel` explicitly does *not* enable `kv_unified` with it - that
stays `false` per `common/common.h` - so the context starts being divided.
`--kv-unified`'s own help text says as much: "default: enabled if number of
slots is auto".

So `parallel = 2` costs half the context, and does it at request time, long
after the config looked fine at startup. Either drop the line and let it stay
auto (4 slots, full context each), or keep it and add `kv-unified = true`:

```ini
[Coder]
ctx-size = 131072
parallel = 2
kv-unified = true
```

Note the two settings trade against each other in memory: divided caches
reserve `ctx-size` in total, while a unified cache lets any one sequence use
all of it, so two long concurrent requests contend.

## troubleshoot.sh

`troubleshoot.sh` checks all of the above without changing anything:

```sh
contrib/gx10-deploy/troubleshoot.sh                     # on the server
BASE=https://llama.example.local:8443 LLAMA_API_KEY=... \
  contrib/gx10-deploy/troubleshoot.sh                   # from a workstation
contrib/gx10-deploy/troubleshoot.sh --load              # also load idle models
```

It reports configured vs actually-usable context per model, flags any section
setting `parallel` without `kv-unified`, rejects router-identity keys that have
crept into `config.yaml`, verifies every `hf-repo` resolves, and warns about
`LLAMA_ARG_*` leaking in from `/etc/environment`. Without `--load` it only
reads state, so it is safe to run against a busy server; unloaded models simply
report no effective context until you pass `--load`.

## Notes

- `ProtectHome=true` in the unit means the service cannot see your own
  `~/.cache/huggingface` - install.sh offers to copy it into the service's
  own cache directory during install.
- GPU access needs `/dev/nvidia*`; install.sh adds the service account to
  whichever of the `video`/`render` groups exist on this system. If the
  service fails to initialize CUDA, check `ls -l /dev/nvidia*` against
  `id llama-server`.
- The audit log (`/var/log/llama-server/audit.jsonl`) is JSON-lines, never
  contains raw keys/tokens - see `docs/design/pr2-principal-proxy.md`.
