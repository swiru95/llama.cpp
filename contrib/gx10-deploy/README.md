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

Then edit `/etc/llama-server/config.yaml` (the API key placeholder must be
changed) and `/etc/llama-server/models.ini` (which models to serve), and:

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
