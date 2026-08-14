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
